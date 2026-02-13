##define _CRT_SECURE_NO_WARNINGS
#define EMPTY 0
#define NUM_PRIORITIES 6
#include <stdio.h>
#include "THREADSLib.h"
#include "Scheduler.h"
#include "Processes.h"

void readyq_push(Process* proc);  //fixed the 2371 error
Process* readyq_pop_highest(void);
Process* readyq_remove_pid(int pid);
Process* readyProcs[NUM_PRIORITIES];
Process processTable[MAXPROC];
Process* runningProcess = NULL;
int nextPid = 1;
int debugFlag = 1;

static void initialize_process_table();
static int watchdog(char*);
static inline void disableInterrupts();
static inline void enable_interrupts();
static int clamp_priority(int priority);
void dispatcher();
static int launch(void*);
static void check_deadlock();
static void DebugConsole(format, ...);
static void clock_handler(char* devicename, uint8_t command, uint32_t status);


/* DO NOT REMOVE */
extern int SchedulerEntryPoint(void* pArgs);
int check_io_scheduler();
check_io_function check_io;


/*************************************************************************
   bootstrap()

   Purpose - This is the first function called by THREADS on startup.

             The function must setup the OS scheduler and primitive
             functionality and then spawn the first two processes.

             The first two process are the watchdog process
             and the startup process SchedulerEntryPoint.

             The statup process is used to initialize additional layers
             of the OS.  It is also used for testing the scheduler
             functions.

   Parameters - Arguments *pArgs - these arguments are unused at this time.

   Returns - The function does not return!

   Side Effects - The effects of this function is the launching of the kernel.

 *************************************************************************/
int bootstrap(void* pArgs)
{
    int result; /* value returned by call to spawn() */

    /* set this to the scheduler version of this function.*/
    check_io = check_io_scheduler;

    /* Initialize the process table. */
    initialize_process_table();





    /* Initialize the Ready list, etc. */
    for (int i = 0; i < NUM_PRIORITIES; i++)
    {
        readyProcs[i] = NULL;
    }
    //readyProcs[0] = NULL;

    /* Initialize the clock interrupt handler */
    interrupt_handler_t* handlers;
    handlers = get_interrupt_handlers();
    handlers[THREADS_TIMER_INTERRUPT] = time_slice;  //removed the comment out


    /* startup a watchdog process */
    result = k_spawn("watchdog", watchdog, NULL, THREADS_MIN_STACK_SIZE, LOWEST_PRIORITY);
    if (result < 0)
    {
        console_output(debugFlag, "Scheduler(): spawn for watchdog returned an error (%d), stopping...\n", result);
        stop(1);
    }

    /*start the test process, which is the main for each test program.*/
    result = k_spawn("Scheduler", SchedulerEntryPoint, NULL, 2 * THREADS_MIN_STACK_SIZE, HIGHEST_PRIORITY);
    if (result < 0)
    {
        console_output(debugFlag, "Scheduler(): spawn for SchedulerEntryPoint returned an error (%d), stopping...\n", result);
        stop(1);
    }
    enable_interrupts();
    dispatcher();

    /*Initialized and ready to go!!*/

    /*This should never return since we are not a real process.*/

    stop(-3);
    return 0;

}

/*************************************************************************
   k_spawn()

   Purpose - spawns a new process.

             Finds an empty entry in the process table and initializes
             information of the process.  Updates information in the
             parent process to reflect this child process creation.

   Parameters - the process's entry point function, the stack size, and
                the process's priority.

   Returns - The Process ID (pid) of the new child process
             The function must return if the process cannot be created.

************************************************************************ */
int k_spawn(char* name, int (*entryPoint)(void*), void* arg, int stacksize, int priority)
{
    int proc_slot = -1;
    struct _process* pNewProc;
    Process* pParent;

    disableInterrupts();

    /* Validate all parameters */
    /* Check for NULL name or entryPoint */
    if (name == NULL || entryPoint == NULL)
    {
        enable_interrupts();
        return -1;
    }

    /* Check name length - must not exceed THREADS_MAX_NAME */
    if (strlen(name) >= THREADS_MAX_NAME)
    {
        console_output(debugFlag, "k_spawn(): Process name is too long.  Halting...\n");
        stop(1);
    }

    /* Check arg length if provided - must not exceed THREADS_MAX_NAME */
    if (arg != NULL && strlen((char*)arg) >= THREADS_MAX_NAME)
    {
        console_output(debugFlag, "k_spawn(): Process arguments are too long.  Halting...\n");
        stop(1);
    }

    /* Validate stack size - must be at least THREADS_MIN_STACK_SIZE */
    if (stacksize < THREADS_MIN_STACK_SIZE)
    {
        enable_interrupts();
        return -2;
    }

    /* Validate priority - must be in range [LOWEST_PRIORITY, HIGHEST_PRIORITY] */
    if (priority < LOWEST_PRIORITY || priority > HIGHEST_PRIORITY)
    {
        enable_interrupts();
        return -3;
    }

    /* Find empty process table slot */
    proc_slot = findEmptyProcessSlot();
    if (proc_slot < 0)
    {
        enable_interrupts();
        return -4;
    }

    /* Initialize the new process slot in the process table */
    pNewProc = &processTable[proc_slot];
    pNewProc->pid = nextPid++;
    pNewProc->status = STATUS_READY;
    pNewProc->priority = clamp_priority(priority);
    pNewProc->entryPoint = entryPoint;
    pNewProc->stacksize = stacksize;
    pNewProc->exitCode = 0;
    pNewProc->signaled = 0;
    pNewProc->numChildren = 0;
    pNewProc->startTime = system_clock() * 1000;
    pNewProc->cpuTime = 0;
    pNewProc->lastDispatchTime = 0;
    pNewProc->nextReadyProcess = NULL;

    strcpy(pNewProc->name, name);
    if (arg != NULL)
        strcpy(pNewProc->startArgs, (char*)arg);
    else
        pNewProc->startArgs[0] = '\0';

    /* Link child to parent */
    if (runningProcess != NULL)
    {
        pNewProc->pParent = runningProcess;

        /* Insert child at head of parent's child list */
        pNewProc->nextSiblingProcess = runningProcess->pChildren;
        runningProcess->pChildren = pNewProc;

        /* Increment child count */
        runningProcess->numChildren++;
    }
    else
    {
        pNewProc->pParent = NULL;
    }

    /* Initialize the process context */
    pNewProc->context = context_initialize(launch, stacksize, arg);

    /* Add the process to the ready queue */
    readyq_push(pNewProc);

    enable_interrupts();

    DebugConsole("k_spawn(): process %s (pid %d) created with priority %d and stack size %d\n", 
                 name, pNewProc->pid, pNewProc->priority, pNewProc->stacksize);

    return pNewProc->pid;

} /* spawn */

/**************************************************************************
   Name - launch

   Purpose - Utility function that makes sure the environment is ready,
             such as enabling interrupts, for the new process.

   Parameters - none

   Returns - nothing
*************************************************************************/
static int launch(void* args)
{
    int exitCode;
    DebugConsole("launch(): started: %s\n", runningProcess->name);

    /* Enable interrupts */
    enable_interrupts();
    exitCode =runningProcess->entryPoint(args); // call the entry point function for this process and capture the exit code when it returns
    // We are now running in the context of the new process, so we can call the function that was passed in as the entry point for this process.  We will also pass in the arguments that were passed to k_spawn as the argument to the entry point function.
    //clamp_priority(runningProcess->priority); // make sure the priority is clamped to the valid range before we start running the process, just in case it was changed after the process was created but before it was launched
    //SchedulerEntryPoint(args);
    


     
    /* Stop the process gracefully */
     // wait for any child processes to exit and get their exit codes, but ignore the return value since we are exiting anyway
    
    k_exit(exitCode); // exit the process with the return value from the entry point function as the exit code
    return 0;
}

/**************************************************************************
   Name - k_wait

   Purpose - Wait for a child process to quit.  Return right away if
             a child has already quit.

   Parameters - Output parameter for the child's exit code.

   Returns - the pid of the quitting child, or
        -4 if the process has no children
        -5 if the process was signaled in the join

************************************************************************ */
int  k_wait(int* pChildExitCode)
{
    Process* child;
    int childPid;
    int hasActiveChildren;

    if (pChildExitCode == NULL)
    {
        return -1;
    }

    while (1)
    {
        disableInterrupts();

        if (runningProcess == NULL)
        {
            enable_interrupts();
            return -1;
        }

        /* Check if signaled while waiting */
        if (runningProcess->signaled)
        {
            enable_interrupts();
            return -5;
        }

        /* Look for a child that has already exited */
        child = runningProcess->pChildren;
        while (child != NULL)
        {
            if (child->status == STATUS_QUIT)
            {
                childPid = child->pid;
                *pChildExitCode = child->exitCode;

                /* Remove child from parent's list */
                if (child == runningProcess->pChildren)
                {
                    runningProcess->pChildren = child->nextSiblingProcess;
                }
                else
                {
                    Process* temp = runningProcess->pChildren;
                    while (temp != NULL && temp->nextSiblingProcess != child)
                        temp = temp->nextSiblingProcess;
                    if (temp != NULL)
                        temp->nextSiblingProcess = child->nextSiblingProcess;
                }

                /* Clean up the exited process */
                child->status = EMPTY;
                child->pid = -1;
                runningProcess->numChildren--;

                enable_interrupts();
                return childPid;
            }
            child = child->nextSiblingProcess;
        }

        /* Check if there are any active (non-exited) children */
        hasActiveChildren = 0;
        child = runningProcess->pChildren;
        while (child != NULL)
        {
            if (child->status != STATUS_QUIT && child->status != EMPTY)
            {
                hasActiveChildren = 1;
                break;
            }
            child = child->nextSiblingProcess;
        }

        /* If there are active children, block the process and dispatch to another */
        if (hasActiveChildren)
        {
            DebugConsole("k_wait(): process %s (pid %d) blocked waiting for children\n",
                runningProcess->name, runningProcess->pid);
            runningProcess->status = STATUS_BLOCKED;
            enable_interrupts();
            dispatcher();
            /* When resumed here (after a child exits and unblocks us), loop back to check for exited children */
        }
        else
        {
            /* If no active children and no exited children, return error */
            enable_interrupts();
            return -1;
        }
    }
}

/**************************************************************************
   Name - k_exit

   Purpose - Exits a process and coordinates with the parent for cleanup
             and return of the exit code.

   Parameters - the code to return to the grieving parent

   Returns - nothing

*************************************************************************/
void k_exit(int code)
{
    Process* parent;

    disableInterrupts();

    if (runningProcess == NULL)
    {
        enable_interrupts();
        dispatcher();
        return;
    }

    /* Check if process has active children - cannot exit */
    if (runningProcess->numChildren > 0)
    {
        console_output(debugFlag, "k_exit(): Process %d has %d children.  Cannot exit until all children have exited.\n", 
                      runningProcess->pid, runningProcess->numChildren);
        enable_interrupts();
        stop(1);
    }

    /* Override exit code to -5 if the process was signaled */
    if (runningProcess->signaled)
    {
        runningProcess->exitCode = -5;
        DebugConsole("k_exit(): Process %d was signaled to quit. Exiting with code -5.\n", runningProcess->pid);
    }
    else
    {
        runningProcess->exitCode = code;
    }

    /* Mark process as quit */
    runningProcess->status = STATUS_QUIT;

    /* Notify parent process */
    parent = runningProcess->pParent;
    if (parent != NULL)
    {
        parent->numChildren--;

        /* Unblock parent if it was waiting for children */
        if (parent->status == STATUS_BLOCKED)
        {
            parent->status = STATUS_READY;
            readyq_push(parent);
        }
    }

    DebugConsole("k_exit(): Process %d (pid %d) exiting with code %d\n", 
                runningProcess->pid, runningProcess->pid, runningProcess->exitCode);

    runningProcess = NULL;

    enable_interrupts();

    /* Dispatch to next process - does not return */
    dispatcher();
}

/**************************************************************************
   Name - k_kill

   Purpose - Signals a process with the specified signal

   Parameters - Signal to send

   Returns -
*************************************************************************/
int k_kill(int pid, int signal)
{
    Process* targetProcess;

    disableInterrupts();

    /* Validate signal - only SIG_TERM is supported */
    if (signal != SIG_TERM)
    {
        console_output(debugFlag, "k_kill(): Invalid signal value.  Halting...\n");
        enable_interrupts();
        stop(1);
    }

    /* Find the target process in the process table */
    targetProcess = findProcessByPid(pid);
    if (targetProcess == NULL)
    {
        console_output(debugFlag, "k_kill(): No process with pid %d found.  Halting...\n", pid);
        enable_interrupts();
        stop(1);
    }

    /* Mark the process as signaled */
    targetProcess->signaled = 1;

    /* If the target process is blocked, unblock it so it can handle the signal */
    if (targetProcess->status == STATUS_BLOCKED)
    {
        targetProcess->status = STATUS_READY;
        readyq_push(targetProcess);
    }

    enable_interrupts();

    return 0;
}


/**************************************************************************
   Name - k_getpid

   Purpose - Returns the process ID of the calling process.

   Parameters - None

   Returns - The process ID of the currently running process
   
*************************************************************************/
int k_getpid()
{
    if (runningProcess == NULL)
        return -1;
    return runningProcess->pid;

}

/**************************************************************************
   Name - k_join
***************************************************************************/
int k_join(int pid, int* pChildExitCode)
{
    Process* targetProcess;

    if (pChildExitCode == NULL)
    {
        return -1;
    }

    disableInterrupts();

    if (runningProcess == NULL)
    {
        enable_interrupts();
        return -1;
    }

    /* Cannot join with self */
    if (pid == runningProcess->pid)
    {
        console_output(debugFlag, "k_join(): A process cannot join on itself.\n");
        stop(1);
    }

    /* Find the target process in the process table */
    targetProcess = findProcessByPid(pid);
    if (targetProcess == NULL)
    {
        console_output(debugFlag, "k_join(): No process with pid %d found.\n", pid);
        enable_interrupts();
        stop(1);
    }

    /* Cannot join with parent */
    if (targetProcess == runningProcess->pParent)
    {
        console_output(debugFlag, "k_join(): A process cannot join on its parent.\n");
        enable_interrupts();
        stop(2);
    }

    /* Wait for the target process to quit */
    while (targetProcess->status != STATUS_QUIT)
    {
        enable_interrupts();
        disableInterrupts();

        /* Check if signaled while waiting */
        if (runningProcess->signaled)
        {
            enable_interrupts();
            return -5;
        }

        /* Re-find the target in case process table changed */
        targetProcess = findProcessByPid(pid);
        if (targetProcess == NULL)
        {
            enable_interrupts();
            return 0;
        }
    }

    /* Retrieve the exit code from the quit process */
    *pChildExitCode = targetProcess->exitCode;

    enable_interrupts();

    return 0;
}

/**************************************************************************
   Name - unblock
*************************************************************************/
int unblock(int pid)
{
    Process* targetProcess; // find the process with the specified pid in the process table
    disableInterrupts();

    targetProcess = readyq_remove_pid(pid);// remove the target process from the ready queue if it's there
    if (targetProcess == NULL || targetProcess->status <= 10) // check if the target process is valid and is currently blocked (status > 10)
    {
        enable_interrupts();
        return(-1);
    }
    targetProcess->status = STATUS_READY; // set the target process status to ready
    readyq_push(targetProcess); // add the target process back to the ready queue
    enable_interrupts();
    return 0; // return 0 for success
}

/*************************************************************************
   Name - block
*************************************************************************/
int block(int blockStatus)
{
    disableInterrupts();
    if (blockStatus <= 10) // we can define some block status codes if we want, but for now just check that it's a valid value
    {
        console_output(debugFlag, "block(): Invalid block status value.\n");
        stop(1);
    }
    if (runningProcess == NULL)// if there is no running process, we cannot block, so return -1 to indicate an error
    {
        enable_interrupts(); // enable interrupts before returning since we disabled them at the start of the function
        return -1;
    }
    if (runningProcess->signaled)// if the process has been signaled to quit, return -5 to indicate that it should not block and should instead exit
    {
        enable_interrupts();
        return -5;
    }
    runningProcess->status = blockStatus;// set the process status to the specified block status
    enable_interrupts();// enable interrupts before calling thedispatcher
    dispatcher();// call the dispatcher to switch to another process since the current process is now blocked
    return 0; // return value is not used, but we can return 0 for success
}

/*************************************************************************
   Name - signaled
*************************************************************************/
int signaled()
{
    if (runningProcess == NULL)
        return 0;
    return runningProcess->signaled;
}
/*************************************************************************
   Name - readtime
*************************************************************************/
int read_time()
{
    if (runningProcess == NULL)
        return 0;
    return runningProcess->cpuTime;
}

/*************************************************************************
   Name - readClock
*************************************************************************/
DWORD read_clock()
{
    return system_clock(); // read the current time from the system clock
}

void display_process_table()
{
    int i;
    char StatusStr[32];
    console_output(debugFlag, "%-5s %-7s %-10s %-12s %-6s %-8s %s\n", "PID", "Parent", "Priority", "Status", "#KIDS", "CPUtime", "Name"); // header for the process table

    for (i = 0; i < MAX_PROCESSES; i++)
    {
        if (processTable[i].status != STATUS_EMPTY) // only display processes that are not empty
        {
            switch (processTable[i].status) // convert the status code to a string for display
            {
            case STATUS_READY: // if the process is ready, set the status string to "READY"
                strcpy(StatusStr, "READY");
                break;
            case STATUS_RUNNING: // if the process is running, set the status string to "RUNNING"
                strcpy(StatusStr, "RUNNING");
                break;
            case STATUS_BLOCKED: // if the process is blocked, set the status string to "BLOCKED"
                strcpy(StatusStr, "BLOCKED");
                break;
            case STATUS_QUIT: // if the process has quit, set the status string to "QUIT"
                strcpy(StatusStr, "QUIT");
                break;
            default:
                strcpy(StatusStr, "UNKNOWN");// if the status code is not recognized, set the status string to "UNKNOWN"
            }
            console_output(debugFlag, "%-5d %-7d %-10d %-12s %-6d %-8d %s\n",
                processTable[i].pid,
                processTable[i].pParent ? processTable[i].pParent->pid : -1,// print the parent process ID or -1 if there is no parent
                processTable[i].priority,// print the process priority
                StatusStr,
                processTable[i].numChildren,// print the number of children processes
                processTable[i].cpuTime, //print the CPU time used by the process
                processTable[i].name);// print the process information in a formatted way
        }
    }
}

/**************************************************************************
   Name - dispatcher

   Purpose - This is where context changes to the next process to run.

   Parameters - none

   Returns - nothing

*************************************************************************/
void dispatcher()
{
    Process* nextProcess = NULL;
    uint32_t currentTime;

    disableInterrupts();

    /* If current process is still running, return it to ready queue */
    if (runningProcess != NULL && runningProcess->status == STATUS_RUNNING)
    {
        runningProcess->status = STATUS_READY;
        readyq_push(runningProcess);
    }

    /* Pop the highest priority process from ready queue */
    nextProcess = readyq_pop_highest();
    if (nextProcess == NULL)
    {
        console_output(debugFlag, "dispatcher(): No ready process found!  Stopping...\n");
        enable_interrupts();
        stop(3);
    }

    /* Set the next process as running */
    runningProcess = nextProcess;
    runningProcess->status = STATUS_RUNNING;
    currentTime = read_clock();
    runningProcess->lastDispatchTime = currentTime;

    DebugConsole("dispatcher(): switching to process %s (pid %d)\n", runningProcess->name, runningProcess->pid);

    /* Enable interrupts and perform context switch */
    enable_interrupts();
    context_switch(runningProcess->context);
}


/**************************************************************************
   Name - watchdog

   Purpose - The watchdoog keeps the system going when all other
         processes are blocked.  It can be used to detect when the system
         is shutting down as well as when a deadlock condition arises.

   Parameters - none

   Returns - nothing
   *************************************************************************/
static int watchdog(char* dummy)
{
    DebugConsole("watchdog(): called\n");
    while (1)
    {
        check_deadlock();
    }
    return 0;
}

/* check to determine if deadlock has occurred... */
static void check_deadlock()
{
    int i;
    int activeProcesses = 0;
    int readyProcesses = 0;
    int runningProcesses = 0;

    /* Count all active processes (excluding watchdog which is runningProcess) */
    for (i = 0; i < MAXPROC; i++)
    {
        if (processTable[i].status != STATUS_EMPTY && processTable[i].status != STATUS_QUIT)
        {
            /* Don't count the watchdog itself */
            if (processTable[i].pid != runningProcess->pid)
            {
                activeProcesses++;
            }

            /* Count ready and running processes (excluding watchdog) */
            if (processTable[i].pid != runningProcess->pid)
            {
                if (processTable[i].status == STATUS_READY)
                {
                    readyProcesses++;
                }
                else if (processTable[i].status == STATUS_RUNNING)
                {
                    runningProcesses++;
                }
            }
        }
    }

    /* Condition 1: No Remaining Processes - Exit gracefully */
    if (activeProcesses == 0)
    {
        console_output(debugFlag, "watchdog(): no remaining processes.  Stopping...\n");
        stop(0);
    }

    /* Condition 2: Remaining Processes - Check for deadlock */
    if (activeProcesses > 0)
    {
        /* Since there is no I/O, if the watchdog is running (idle),
           there must be at least one other process ready or running.
           If not, this is a deadlock condition. */
        if (readyProcesses == 0 && runningProcesses == 0)
        {
            console_output(debugFlag, "watchdog(): deadlock detected. Processes exist but none are ready or running.  Stopping...\n");
            stop(1);
        }
    }
}

/*
 * Disables the interrupts.
 */
static inline void disableInterrupts()
{
    /* We ARE in kernel mode */
    int psr = get_psr();
    psr = psr & ~PSR_INTERRUPTS;
    set_psr(psr);
}
/* disableInterrupts */
static inline void enable_interrupts()
{
    int psr = get_psr();

    psr = psr | PSR_INTERRUPTS; // enable interrupts

    set_psr(psr);
}
/* We ARE in kernel mode */
/**************************************************************************
   Name - DebugConsole
   Purpose - Prints  the message to the console_output if in debug mode
   Parameters - format string and va args
   Returns - nothing
   Side Effects -
*************************************************************************/
static void DebugConsole(char* format, ...)
{
    char buffer[128];
    va_list argptr;

    if (debugFlag)
    {
        va_start(argptr, format);
        vsnprintf(buffer, sizeof(buffer), format, argptr);
        console_output(TRUE, buffer);
        va_end(argptr);

    }
}


/* there is no I/O yet, so return false. */
int check_io_scheduler()
{
    return false;
}



static int clamp_priority(int priority) //
{
    if (priority < 0)
    {
        return 0;
    }
    if (priority >= NUM_PRIORITIES)
    {
        return NUM_PRIORITIES - 1;

    }
    return priority;

}

void readyq_push(Process* proc) // push a process onto the ready queue based on its priority
{
    if (proc == NULL) return;
    int prio = clamp_priority(proc->priority);
    proc->nextReadyProcess = NULL;
    if (readyProcs[prio] == NULL) {
        readyProcs[prio] = proc;
        return;
    }

    Process* cur = readyProcs[prio];
    while (cur->nextReadyProcess != NULL) {
        cur = cur->nextReadyProcess;
    }
    cur->nextReadyProcess = proc;
}

Process* readyq_pop_prio(int prio)
{
    prio = clamp_priority(prio);
    Process* head = readyProcs[prio];
    if (head == NULL) return NULL;
    readyProcs[prio] = head->nextReadyProcess;
    head->nextReadyProcess = NULL;
    return head;
}

Process* readyq_pop_highest(void) // Pop the highest priority process
{
    for (int prio = NUM_PRIORITIES - 1; prio >= 0; prio--)
    {
        if (readyProcs[prio] != NULL)
        {
            return readyq_pop_prio(prio);
        }
    }
    return NULL;
}

Process* readyq_remove_pid(int pid)
{
    Process* target = &processTable[pid % MAXPROC];
    int prio = clamp_priority(target->priority);
    Process* prev = NULL;
    Process* cur = readyProcs[prio];

    while (cur != NULL)
    {
        if (cur == target)
        {
            if (prev == NULL)
            {
                readyProcs[prio] = cur->nextReadyProcess;
            }

            else {
                prev->nextReadyProcess = cur->nextReadyProcess;
            }

            cur->nextReadyProcess = NULL;
            return cur;
        }
        prev = cur;
        cur = cur->nextReadyProcess;
    }
    return NULL;
}

void time_slice(void)
{
    uint32_t currentTime;
    uint32_t elapsedTime;

    if (runningProcess == NULL)
        return;

    currentTime = read_clock();

    /* Calculate elapsed time since last dispatch */
    elapsedTime = currentTime - runningProcess->lastDispatchTime;

    /* Update cumulative CPU time */
    runningProcess->cpuTime += elapsedTime;

    /* Check if quantum (80ms) has been exceeded */
    if (elapsedTime >= 80)
    {
        runningProcess->lastDispatchTime = currentTime;
        dispatcher();
    }
}
static void clock_handler(char* devicename, uint8_t command, uint32_t status)
{
    time_slice();
}

static void initialize_process_table()
{
    int i;
    for (i = 0; i < MAXPROC; i++)
    {
        processTable[i].status = EMPTY;
        processTable[i].pid = -1;
        processTable[i].nextReadyProcess = NULL;
        processTable[i].nextSiblingProcess = NULL;
        processTable[i].pParent = NULL;
        processTable[i].pChildren = NULL;
        processTable[i].numChildren = 0;
        processTable[i].exitCode = 0;
        processTable[i].signaled = 0;
        processTable[i].cpuTime = 0;
        processTable[i].startTime = 0;
        processTable[i].lastDispatchTime = 0;
    }

    readyq_push(NULL); // initialize the ready queue with a NULL value to indicate that it's empty
    nextPid = 1; // start at 1 since 0 is reserved for the null process
}

static int findEmptyProcessSlot()
{
    for (int i = 0; i < MAXPROC; i++)// loop through the process table to find an empty slot
    {
        if (processTable[i].status == STATUS_EMPTY)
        {
            return i;
        }
    }
    return -1; // no empty slot found
}

static Process* findProcessByPid(int pid)
{
    for (int i = 0; i < MAXPROC; i++)// loop through the process table to find the process with the specified pid
    {
        if (processTable[i].pid == pid && processTable[i].status != STATUS_EMPTY)
        {
            return &processTable[i];
        }
    }
    return NULL; // no process with the specified pid found
}