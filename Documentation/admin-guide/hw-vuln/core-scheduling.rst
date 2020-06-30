Core Scheduling
***************
Core scheduling support allows userspace to define groups of tasks that can
share a core. These groups can be specified either for security usecases (one
group of tasks don't trust another), or for performance usecases (some
workloads may benefit from running on the same core as they don't need the same
hardware resources of the shared core).

Security usecase
----------------
A cross-HT attack involves the attacker and victim running on different
Hyper Threads of the same core. MDS and L1TF are examples of such attacks.
Without core scheduling, the only full mitigation of cross-HT attacks is to
disable Hyper Threading (HT). Core scheduling allows HT to be turned on safely
by ensuring that trusted tasks can share a core. This increase in core sharing
can improvement performance, however it is not guaranteed that performance will
always improve, though that is seen to be the case with a number of real world
workloads. In theory, core scheduling aims to perform at least as good as when
Hyper Threading is disabled. In practice, this is mostly the case though not
always: as synchronizing scheduling decisions across 2 or more CPUs in a core
involves additional overhead - especially when the system is lightly loaded
(``total_threads <= N/2``, where N is the total number of CPUs).

Usage
-----
Core scheduling support is enabled via the ``CONFIG_SCHED_CORE`` config option.
Using this feature, userspace defines groups of tasks that can be co-scheduled
on the same core.
The core scheduler uses this information to make sure that tasks that are not
in the same group never run simultaneously on a core, while doing its best to
satisfy the system's scheduling requirements.

There are 2 ways to use core-scheduling:

CGroup
######
Core scheduling adds additional files to the CPU controller CGroup:

* ``cpu.core_tag``
Writing ``1`` into this file results in all tasks in the group getting tagged.
This results in all the CGroup's tasks allowed to run concurrently on a core's
hyperthreads (also called siblings).

The file being a value of ``0`` means the tag state of the CGroup is inherited
from its parent hierarchy. If any ancestor of the CGroup is tagged, then the
group is tagged.

.. note:: Once a CGroup is tagged via cpu.core_tag, it is not possible to set this
          for any descendant of the tagged group.

.. note:: When a CGroup is not tagged, all the tasks within the group can share
          a core with kernel threads and untagged system threads. For this reason,
          if a group has ``cpu.core_tag`` of 0, it is considered to be trusted.

prctl interface
###############
A ``prtcl(2)`` command ``PR_SCHED_CORE_SHARE`` provides an interface for the
creation of and admission and removal of tasks from core scheduling groups.

::

    #include <sys/prctl.h>

    int prctl(int option, unsigned long arg2, unsigned long arg3,
            unsigned long arg4, unsigned long arg5);

option:
    ``PR_SCHED_CORE_SHARE``

arg2:
    - ``PR_SCHED_CORE_CLEAR            0  -- clear core_sched cookie of pid``
    - ``PR_SCHED_CORE_SHARE_FROM       1  -- get core_sched cookie from pid``
    - ``PR_SCHED_CORE_SHARE_TO         2  -- push core_sched cookie to pid``

arg3:
    ``tid`` of the task for which the operation applies

arg4 and arg5:
    MUST be equal to 0.

Creation
~~~~~~~~
Creation is accomplished by sharing a ''cookie'' from a process not currently in
a core scheduling group.

::

    if (prctl(PR_SCHED_CORE_SHARE, PR_SCHED_CORE_SHARE_FROM, src_tid, 0, 0) < 0)
            handle_error("src_tid sched_core failed");

Removal
~~~~~~~
Removing a task from a core scheduling group is done by:

::

    if (prctl(PR_SCHED_CORE_SHARE, PR_SCHED_CORE_SHARE_CLEAR, clr_tid, 0, 0) < 0)
             handle_error("clr_tid sched_core failed");

Cookie Transferal
~~~~~~~~~~~~~~~~~
Transferring a cookie between the current and other tasks is possible using
PR_SCHED_CORE_SHARE_FROM and PR_SCHED_CORE_SHARE_TO to inherit a cookie from a
specified task or a share a cookie with a task. In combination this allows a
simple helper program to pull a cookie from a task in an existing core
scheduling group and share it with already running tasks.

::

    if (prctl(PR_SCHED_CORE_SHARE, PR_SCHED_CORE_SHARE_FROM, from_tid, 0, 0) < 0)
            handle_error("from_tid sched_core failed");

    if (prctl(PR_SCHED_CORE_SHARE, PR_SCHED_CORE_SHARE_TO, to_tid, 0, 0) < 0)
            handle_error("to_tid sched_core failed");


.. note:: The core-sharing granted with ``prctl(2)`` will be subject to
          core-sharing restrictions specified by the CGroup interface. For example,
          if tasks T1 and T2 are a part of 2 different tagged CGroups, then they will
          not share a core even if ``prctl(2)`` is called. This is analogous to how
          affinities are set using the cpuset interface.

It is important to note that, on a ``clone(2)`` syscall with ``CLONE_THREAD`` set,
the child will be assigned the same ''cookie'' as its parent and thus in the
same core scheduling group.  In the security usecase, a ``CLONE_THREAD`` child
can access its parent's address space anyway (``CLONE_THREAD`` requires
``CLONE_SIGHAND`` which requires ``CLONE_VM``), so there's no point in not
allowing them to share a core. If a different behavior is desired, the child
thread can call ``prctl(2)`` as needed.  This behavior is specific to the
``prctl(2)`` interface. For the CGroup interface, the child of a fork always
shares a core with its parent.  On the other hand, if a parent was previously
tagged via ``prctl(2)`` and does a regular ``fork(2)`` syscall, the child will
receive a unique tag.

Design/Implementation
---------------------
Each task that is tagged is assigned a cookie internally in the kernel. As
mentioned in `Usage`_, tasks with the same cookie value are assumed to trust
each other and share a core.

The basic idea is that, every schedule event tries to select tasks for all the
siblings of a core such that all the selected tasks running on a core are
trusted (same cookie) at any point in time. Kernel threads are assumed trusted.
The idle task is considered special, as it trusts everything and everything
trusts it.

During a schedule() event on any sibling of a core, the highest priority task on
the sibling's core is picked and assigned to the sibling calling schedule(), if
the sibling has the task enqueued. For rest of the siblings in the core,
highest priority task with the same cookie is selected if there is one runnable
in their individual run queues. If a task with same cookie is not available,
the idle task is selected.  Idle task is globally trusted.

Once a task has been selected for all the siblings in the core, an IPI is sent to
siblings for whom a new task was selected. Siblings on receiving the IPI will
switch to the new task immediately. If an idle task is selected for a sibling,
then the sibling is considered to be in a `forced idle` state. I.e., it may
have tasks on its on runqueue to run, however it will still have to run idle.
More on this in the next section.

Forced-idling of tasks
----------------------
The scheduler tries its best to find tasks that trust each other such that all
tasks selected to be scheduled are of the highest priority in a core.  However,
it is possible that some runqueues had tasks that were incompatible with the
highest priority ones in the core. Favoring security over fairness, one or more
siblings could be forced to select a lower priority task if the highest
priority task is not trusted with respect to the core wide highest priority
task.  If a sibling does not have a trusted task to run, it will be forced idle
by the scheduler (idle thread is scheduled to run).

When the highest priority task is selected to run, a reschedule-IPI is sent to
the sibling to force it into idle. This results in 4 cases which need to be
considered depending on whether a VM or a regular usermode process was running
on either HT::

          HT1 (attack)            HT2 (victim)
   A      idle -> user space      user space -> idle
   B      idle -> user space      guest -> idle
   C      idle -> guest           user space -> idle
   D      idle -> guest           guest -> idle

Note that for better performance, we do not wait for the destination CPU
(victim) to enter idle mode. This is because the sending of the IPI would bring
the destination CPU immediately into kernel mode from user space, or VMEXIT
in the case of guests. At best, this would only leak some scheduler metadata
which may not be worth protecting. It is also possible that the IPI is received
too late on some architectures, but this has not been observed in the case of
x86.

Trust model
-----------
Core scheduling maintains trust relationships amongst groups of tasks by
assigning the tag of them with the same cookie value.
When a system with core scheduling boots, all tasks are considered to trust
each other. This is because the core scheduler does not have information about
trust relationships until userspace uses the above mentioned interfaces, to
communicate them. In other words, all tasks have a default cookie value of 0.
and are considered system-wide trusted. The stunning of siblings running
cookie-0 tasks is also avoided.

Once userspace uses the above mentioned interfaces to group sets of tasks, tasks
within such groups are considered to trust each other, but do not trust those
outside. Tasks outside the group also don't trust tasks within.

Limitations in core-scheduling
------------------------------
Core scheduling tries to guarantee that only trusted tasks run concurrently on a
core. But there could be small window of time during which untrusted tasks run
concurrently or kernel could be running concurrently with a task not trusted by
kernel.

1. IPI processing delays
########################
Core scheduling selects only trusted tasks to run together. IPI is used to notify
the siblings to switch to the new task. But there could be hardware delays in
receiving of the IPI on some arch (on x86, this has not been observed). This may
cause an attacker task to start running on a CPU before its siblings receive the
IPI. Even though cache is flushed on entry to user mode, victim tasks on siblings
may populate data in the cache and micro architectural buffers after the attacker
starts to run and this is a possibility for data leak.

Open cross-HT issues that core scheduling does not solve
--------------------------------------------------------
1. For MDS
##########
Core scheduling cannot protect against MDS attacks between an HT running in
user mode and another running in kernel mode. Even though both HTs run tasks
which trust each other, kernel memory is still considered untrusted. Such
attacks are possible for any combination of sibling CPU modes (host or guest mode).

2. For L1TF
###########
Core scheduling cannot protect against an L1TF guest attacker exploiting a
guest or host victim. This is because the guest attacker can craft invalid
PTEs which are not inverted due to a vulnerable guest kernel. The only
solution is to disable EPT (Extended Page Tables).

For both MDS and L1TF, if the guest vCPU is configured to not trust each
other (by tagging separately), then the guest to guest attacks would go away.
Or it could be a system admin policy which considers guest to guest attacks as
a guest problem.

Another approach to resolve these would be to make every untrusted task on the
system to not trust every other untrusted task. While this could reduce
parallelism of the untrusted tasks, it would still solve the above issues while
allowing system processes (trusted tasks) to share a core.

3. Protecting the kernel (IRQ, syscall, VMEXIT)
###############################################
This section is a work in progress. The main point here is entry into the
kernel is not protected from attackers on a sibling.

Use cases
---------
The main use case for Core scheduling is mitigating the cross-HT vulnerabilities
with SMT enabled. There are other use cases where this feature could be used:

- Isolating tasks that needs a whole core: Examples include realtime tasks, tasks
  that uses SIMD instructions etc.
- Gang scheduling: Requirements for a group of tasks that needs to be scheduled
  together could also be realized using core scheduling. One example is vCPUs of
  a VM.
