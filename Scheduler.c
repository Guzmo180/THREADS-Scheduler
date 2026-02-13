#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "THREADSLib.h"
#include "Scheduler.h"
#include "Processes.h"

/* Global data structures */
Process processTable[MAX_PROCESSES];
Process *runningProcess = NULL;
Process *readyQueueHead = NULL;      /* Head of ready queue (priority ordered) */
int nextPid = 1;
int debugFlag = 1;

/* Timer constants */
#define TIME_SLICE_QUANTUM 80           /* Time slice in milliseconds */

static int watchdog(char*);
static inline void disableInterrupts();
static inline void enableInterrupts();
void dispatcher();
static int launch(void *);
static void check_deadlock();
static void DebugConsole(char* format, ...);
static void addToReadyQueue(Process *process);
static void removeFromReadyQueue(Process *process);
static void timerInterruptHandler(char deviceId[32], uint8_t command, uint32_t status);

/* DO NOT REMOVE */
extern int SchedulerEntryPoint(void* pArgs);
int check_io_scheduler();
check_io_function check_io;


/*
 * Initialize process table and ready queue
 */
static void initializeProcessTable()
{
    int i;
    for (i = 0; i < MAX_PROCESSES; i++)
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
    readyQueueHead = NULL;
    nextPid = 1;
}

/*
 * Find an empty slot in the process table
 */
static int findEmptyProcessSlot()
{
    int i;
    for (i = 0; i < MAX_PROCESSES; i++)
    {
        if (processTable[i].status == EMPTY)
            return i;
    }
    return -1;  /* No empty slots */
}

/*
 * Get process by PID
 */
static Process* getProcessByPid(int pid)
{
    int i;
    for (i = 0; i < MAX_PROCESSES; i++)
    {
        if (processTable[i].pid == pid && processTable[i].status != EMPTY)
            return &processTable[i];
    }
    return NULL;
}

/*
 * Add a process to the ready queue in priority order
 */
static void addToReadyQueue(Process *process)
{
    Process *current, *prev;

    if (process == NULL)
        return;

    process->nextReadyProcess = NULL;

    /* If queue is empty, add as head */
    if (readyQueueHead == NULL)
    {
        readyQueueHead = process;
        return;
    }

    /* Find correct position based on priority (higher priority = earlier in queue) */
    prev = NULL;
    current = readyQueueHead;
    
    while (current != NULL && current->priority >= process->priority)
    {
        prev = current;
        current = current->nextReadyProcess;
    }

    /* Insert process */
    process->nextReadyProcess = current;
    if (prev == NULL)
        readyQueueHead = process;
    else
        prev->nextReadyProcess = process;
}

/*
 * Remove a process from the ready queue
 */
static void removeFromReadyQueue(Process *process)
{
    Process *current, *prev;

    if (process == NULL || readyQueueHead == NULL)
        return;

    prev = NULL;
    current = readyQueueHead;

    while (current != NULL)
    {
        if (current == process)
        {
            if (prev == NULL)
                readyQueueHead = current->nextReadyProcess;
            else
                prev->nextReadyProcess = current->nextReadyProcess;
            process->nextReadyProcess = NULL;
            return;
        }
        prev = current;
        current = current->nextReadyProcess;
    }
}

/*
 * Timer interrupt handler
 */
static void timerInterruptHandler(char deviceId[32], uint8_t command, uint32_t status)
{
    /* Call time_slice to check if quantum expired */
    time_slice();
}

/*
 * Disables the interrupts
 */
static inline void disableInterrupts()
{
    int psr = get_psr();
    psr = psr & ~PSR_INTERRUPTS;
    set_psr(psr);
}

/*
 * Enables the interrupts
 */
static inline void enableInterrupts()
{
    int psr = get_psr();
    psr = psr | PSR_INTERRUPTS;
    set_psr(psr);
}

/*
 * bootstrap()
 * 
 * This is the first function called by THREADS on startup.
 * The function must setup the OS scheduler and primitive functionality
 * and then spawn the first two processes: watchdog and SchedulerEntryPoint.
 */
int bootstrap(void *pArgs)
{
    int result;
    interrupt_handler_t *interruptHandlers;

    /* Set this to the scheduler version of this function */
    check_io = check_io_scheduler;

    /* Initialize the process table and ready queue */
    initializeProcessTable();

    /* Initialize interrupt handlers - set only timer interrupt */
    interruptHandlers = get_interrupt_handlers();
    interruptHandlers[THREADS_TIMER_INTERRUPT] = timerInterruptHandler;
    interruptHandlers[THREADS_IO_INTERRUPT] = NULL;
    interruptHandlers[THREADS_EXCEPTION_INTERRUPT] = NULL;
    interruptHandlers[THREADS_SYS_CALL_INTERRUPT] = NULL;

    /* Enable interrupts */
    enableInterrupts();

    /* Spawn the watchdog process (lowest priority) */
    result = k_spawn("watchdog", watchdog, NULL, THREADS_MIN_STACK_SIZE, LOWEST_PRIORITY);
    if (result < 0)
    {
        console_output(debugFlag, "bootstrap(): spawn for watchdog returned error (%d)\n", result);
        stop(1);
    }

    /* Spawn the SchedulerEntryPoint process (highest priority) */
    result = k_spawn("Scheduler", SchedulerEntryPoint, NULL, 2 * THREADS_MIN_STACK_SIZE, HIGHEST_PRIORITY);
    if (result < 0)
    {
        console_output(debugFlag, "bootstrap(): spawn for SchedulerEntryPoint returned error (%d)\n", result);
        stop(1);
    }

    /* Dispatch to the first ready process */
    dispatcher();

    /* Should never reach here */
    stop(-3);
    return 0;
}

/*
 * k_spawn()
 * 
 * Spawns a new process with the given parameters.
 * Returns the PID on success, or an error code on failure.
 */
int k_spawn(char* name, int (*entryPoint)(void *), void* arg, int stacksize, int priority)
{
    int proc_slot;
    Process *pNewProc;
    Process *pParent;

    disableInterrupts();

    /* Validate parameters */
    if (name == NULL || entryPoint == NULL)
    {
        enableInterrupts();
        return -1;
    }

    if (strlen(name) >= THREADS_MAX_NAME)
    {
        console_output(debugFlag, "k_spawn(): Process name too long. Halting.\n");
        stop(1);
    }

    if (arg != NULL && strlen((char*)arg) >= THREADS_MAX_NAME)
    {
        console_output(debugFlag, "k_spawn(): Process arguments too long. Halting.\n");
        stop(1);
    }

    /* Validate stack size */
    if (stacksize < THREADS_MIN_STACK_SIZE)
    {
        enableInterrupts();
        return -2;
    }

    /* Validate priority */
    if (priority < LOWEST_PRIORITY || priority > HIGHEST_PRIORITY)
    {
        enableInterrupts();
        return -3;
    }

    /* Find an empty process table slot */
    proc_slot = findEmptyProcessSlot();
    if (proc_slot < 0)
    {
        enableInterrupts();
        return -4;  /* Process table full */
    }

    /* Initialize the new process */
    pNewProc = &processTable[proc_slot];
    pNewProc->pid = nextPid++;
    pNewProc->status = READY;
    pNewProc->priority = priority;
    pNewProc->entryPoint = entryPoint;
    pNewProc->stacksize = stacksize;
    pNewProc->exitCode = 0;
    pNewProc->signaled = 0;
    pNewProc->numChildren = 0;
    pNewProc->startTime = system_clock() * 1000;  /* Convert ms to microseconds */
    pNewProc->cpuTime = 0;
    pNewProc->lastDispatchTime = 0;
    pNewProc->nextSiblingProcess = NULL;

    strcpy(pNewProc->name, name);
    if (arg != NULL)
        strcpy(pNewProc->startArgs, (char*)arg);
    else
        pNewProc->startArgs[0] = '\0';

    /* Set parent process if one exists */
    pParent = runningProcess;
    pNewProc->pParent = pParent;
    pNewProc->pChildren = NULL;

    if (pParent != NULL)
    {
        /* Add to parent's children list */
        pNewProc->nextSiblingProcess = pParent->pChildren;
        pParent->pChildren = pNewProc;
        pParent->numChildren++;
    }
    else
    {
        /* Watchdog and SchedulerEntryPoint have no parent */
        pNewProc->pParent = NULL;
    }

    /* Initialize the process context */
    pNewProc->context = context_initialize(launch, stacksize, arg);

    /* Add to ready queue */
    addToReadyQueue(pNewProc);

    enableInterrupts();

    DebugConsole("k_spawn(): created process %s with pid %d\n", name, pNewProc->pid);

    return pNewProc->pid;
}

/*
 * launch()
 * 
 * Utility function called when a process first starts.
 * Enables interrupts and calls the process entry point.
 */
static int launch(void *args)
{
    int exitCode;

    DebugConsole("launch(): started: %s\n", runningProcess->name);

    /* Enable interrupts for the new process */
    enableInterrupts();

    /* Call the entry point function */
    exitCode = runningProcess->entryPoint(args);

    /* If entry point returns, exit the process */
    k_exit(exitCode);

    return 0;  /* Should never reach here */
}

/*
 * time_slice()
 * 
 * Checks if the currently running process has exceeded its time slice quantum.
 * If so, calls the dispatcher to switch to the next process.
 */
void time_slice()
{
    uint32_t currentTime;

    if (runningProcess == NULL)
        return;

    currentTime = system_clock();

    /* Check if quantum (80ms) has been exceeded */
    if ((currentTime - runningProcess->lastDispatchTime) >= TIME_SLICE_QUANTUM)
    {
        dispatcher();
    }
}

/*
 * dispatcher()
 * 
 * This is the kernel's process scheduler.
 * It selects the next process to run from the ready queue
 * and performs a context switch if necessary.
 */
void dispatcher()
{
    Process *nextProcess;
    uint32_t currentTime;

    disableInterrupts();

    /* Add current process back to ready queue if it's still running */
    if (runningProcess != NULL && runningProcess->status == RUNNING)
    {
        runningProcess->status = READY;
        addToReadyQueue(runningProcess);
        DebugConsole("dispatcher(): added %s (pid %d) back to ready queue\n", 
                    runningProcess->name, runningProcess->pid);
    }

    /* Get the next process from the ready queue */
    if (readyQueueHead == NULL)
    {
        /* No process ready - this is a fatal error, should never happen */
        console_output(debugFlag, "dispatcher(): ERROR - ready queue is empty! Halting.\n");
        enableInterrupts();
        stop(1);
        return;
    }

    nextProcess = readyQueueHead;
    removeFromReadyQueue(nextProcess);

    /* Verify we have a valid process */
    if (nextProcess == NULL)
    {
        console_output(debugFlag, "dispatcher(): ERROR - nextProcess is NULL! Halting.\n");
        enableInterrupts();
        stop(1);
        return;
    }

    /* Update the running process and status */
    runningProcess = nextProcess;
    nextProcess->status = RUNNING;
    currentTime = system_clock();
    nextProcess->lastDispatchTime = currentTime;

    DebugConsole("dispatcher(): switching to process %s (pid %d), current time: %u\n", 
                nextProcess->name, nextProcess->pid, currentTime);

    /* Enable interrupts before context switch */
    enableInterrupts();

    /* Perform the context switch - this should NOT return unless interrupted */
    context_switch(nextProcess->context);
}

/*
 * k_getpid()
 * 
 * Returns the PID of the currently running process.
 */
int k_getpid()
{
    if (runningProcess == NULL)
        return -1;
    return runningProcess->pid;
}

/*
 * signaled()
 * 
 * Checks if the currently running process has been signaled.
 */
int signaled()
{
    if (runningProcess == NULL)
        return 0;
    return runningProcess->signaled;
}

/*
 * k_kill()
 * 
 * Sends a signal to the specified process.
 * The only supported signal is SIG_TERM.
 */
int k_kill(int pid, int signal)
{
    Process *targetProcess;

    disableInterrupts();

    /* Validate signal */
    if (signal != SIG_TERM)
    {
        console_output(debugFlag, "k_kill(): Invalid signal %d. Halting.\n", signal);
        stop(1);
    }

    /* Find the target process */
    targetProcess = getProcessByPid(pid);
    if (targetProcess == NULL)
    {
        console_output(debugFlag, "k_kill(): Invalid process ID %d. Halting.\n", pid);
        stop(1);
    }

    /* Mark process as signaled */
    targetProcess->signaled = 1;

    enableInterrupts();

    return 0;
}

/*
 * k_exit()
 * 
 * Terminates the currently running process.
 * Does not return.
 */
void k_exit(int exitCode)
{
    Process *parent;
    Process *child;

    disableInterrupts();

    if (runningProcess == NULL)
    {
        enableInterrupts();
        return;
    }

    /* Check for active children */
    if (runningProcess->numChildren > 0)
    {
        console_output(debugFlag, "k_exit(): Process %s has %d active children. Halting.\n", 
                      runningProcess->name, runningProcess->numChildren);
        stop(1);
    }

    /* Override exit code if process was signaled */
    if (runningProcess->signaled)
        exitCode = -5;

    /* Mark process as quit and save exit code */
    runningProcess->exitCode = exitCode;
    runningProcess->status = QUIT;

    /* Notify parent if one exists */
    parent = runningProcess->pParent;
    if (parent != NULL)
    {
        parent->numChildren--;
        
        /* If parent is blocked waiting for children, unblock it */
        if (parent->status == WAIT_BLOCK)
        {
            DebugConsole("k_exit(): unblocking parent process %s (pid %d)\n",
                        parent->name, parent->pid);
            parent->status = READY;
            addToReadyQueue(parent);
        }
    }

    DebugConsole("k_exit(): process %s (pid %d) exiting with code %d\n", 
                runningProcess->name, runningProcess->pid, exitCode);

    runningProcess = NULL;

    enableInterrupts();

    /* Dispatch to next process - does not return */
    dispatcher();
}

/*
 * k_wait()
 * 
 * Waits for any child process to exit.
 * Returns the PID of the child that exited, or an error code.
 * If no child has exited but active children exist, blocks the process and dispatcher 
 * allows other processes to run. When a child exits, the parent is unblocked and loops
 * back to collect the exit code.
 */
int k_wait(int* pChildExitCode)
{
    Process *child;
    int childPid = -1;
    int hasActiveChildren;

    if (pChildExitCode == NULL)
        return -1;

    while (1)
    {
        disableInterrupts();

        if (runningProcess == NULL)
        {
            enableInterrupts();
            return -1;
        }

        /* Check if signaled while waiting */
        if (runningProcess->signaled)
        {
            enableInterrupts();
            return -5;
        }

        /* Look for a child that has already exited */
        child = runningProcess->pChildren;
        while (child != NULL)
        {
            if (child->status == QUIT)
            {
                childPid = child->pid;
                *pChildExitCode = child->exitCode;
                
                /* Remove child from parent's list */
                if (child == runningProcess->pChildren)
                    runningProcess->pChildren = child->nextSiblingProcess;
                else
                {
                    Process *temp = runningProcess->pChildren;
                    while (temp != NULL && temp->nextSiblingProcess != child)
                        temp = temp->nextSiblingProcess;
                    if (temp != NULL)
                        temp->nextSiblingProcess = child->nextSiblingProcess;
                }
                
                /* Clean up the exited process */
                child->status = EMPTY;
                child->pid = -1;
                
                enableInterrupts();
                return childPid;
            }
            child = child->nextSiblingProcess;
        }

        /* Check if there are any active (non-exited) children */
        hasActiveChildren = 0;
        child = runningProcess->pChildren;
        while (child != NULL)
        {
            if (child->status != QUIT && child->status != EMPTY)
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
            runningProcess->status = WAIT_BLOCK;
            enableInterrupts();
            dispatcher();
            /* When resumed here (after a child exits and unblocks us), loop back to check for exited children */
        }
        else
        {
            /* If no active children and no exited children, return error */
            enableInterrupts();
            return -1;
        }
    }
}

/*
 * k_join()
 * 
 * Waits for a specific process to terminate.
 */
int k_join(int pid, int* pChildExitCode)
{
    Process *targetProcess;

    if (pChildExitCode == NULL)
        return -1;

    disableInterrupts();

    if (runningProcess == NULL)
    {
        enableInterrupts();
        return -1;
    }

    /* Cannot join with self */
    if (pid == runningProcess->pid)
    {
        console_output(debugFlag, "k_join(): Cannot join with self. Halting.\n");
        stop(1);
    }

    /* Find the target process */
    targetProcess = getProcessByPid(pid);
    if (targetProcess == NULL)
    {
        console_output(debugFlag, "k_join(): Invalid process ID %d. Halting.\n", pid);
        stop(1);
    }

    /* Cannot join with parent */
    if (targetProcess == runningProcess->pParent)
    {
        console_output(debugFlag, "k_join(): Cannot join with parent process. Halting.\n");
        stop(2);
    }

    /* Wait for the process to exit */
    while (targetProcess->status != QUIT)
    {
        /* Block and let other processes run */
        enableInterrupts();
        disableInterrupts();

        /* Check if signaled while waiting */
        if (runningProcess->signaled)
        {
            enableInterrupts();
            return -5;
        }

        targetProcess = getProcessByPid(pid);
        if (targetProcess == NULL)
        {
            enableInterrupts();
            return 0;  /* Process already cleaned up */
        }
    }

    *pChildExitCode = targetProcess->exitCode;

    enableInterrupts();

    return 0;
}

/*
 * block()
 * 
 * Blocks the currently running process with the given status.
 */
int block(int blockStatus)
{
    disableInterrupts();

    if (blockStatus <= 10)
    {
        console_output(debugFlag, "block(): Invalid block status %d. Halting.\n", blockStatus);
        stop(1);
    }

    if (runningProcess == NULL)
    {
        enableInterrupts();
        return -1;
    }

    /* Check if signaled */
    if (runningProcess->signaled)
    {
        enableInterrupts();
        return -5;
    }

    /* Change status and dispatch to next process */
    runningProcess->status = blockStatus;

    DebugConsole("block(): process %s (pid %d) blocked with status %d\n",
                runningProcess->name, runningProcess->pid, blockStatus);

    enableInterrupts();
    dispatcher();

    return 0;
}

/*
 * unblock()
 * 
 * Unblocks a previously blocked process.
 */
int unblock(int pid)
{
    Process *targetProcess;

    disableInterrupts();

    targetProcess = getProcessByPid(pid);
    if (targetProcess == NULL || targetProcess->status <= 10)
    {
        enableInterrupts();
        return -1;
    }

    /* Return process to ready state */
    DebugConsole("unblock(): unblocking process %s (pid %d) from status %d\n",
                targetProcess->name, targetProcess->pid, targetProcess->status);
    targetProcess->status = READY;
    addToReadyQueue(targetProcess);

    enableInterrupts();

    return 0;
}

/*
 * read_time()
 * 
 * Returns the CPU time (in milliseconds) for the currently running process.
 */
int read_time()
{
    if (runningProcess == NULL)
        return 0;
    return runningProcess->cpuTime;
}

/*
 * get_start_time()
 * 
 * Returns the start time (in microseconds) of the currently running process.
 */
int get_start_time()
{
    if (runningProcess == NULL)
        return 0;
    return runningProcess->startTime;
}

/*
 * read_clock()
 * 
 * Returns the current system clock value.
 */
DWORD read_clock()
{
    return system_clock();
}

/*
 * display_process_table()
 * 
 * Displays all non-empty processes in the process table.
 */
void display_process_table()
{
    int i;
    char statusStr[32];

    console_output(debugFlag, "%-5s %-7s %-10s %-12s %-6s %-8s %s\n",
                  "PID", "Parent", "Priority", "Status", "# Kids", "CPUtime", "Name");

    for (i = 0; i < MAX_PROCESSES; i++)
    {
        if (processTable[i].status != EMPTY)
        {
            /* Convert status to string */
            switch (processTable[i].status)
            {
                case READY:     strcpy(statusStr, "READY"); break;
                case RUNNING:   strcpy(statusStr, "RUNNING"); break;
                case WAIT_BLOCK: strcpy(statusStr, "WAIT_BLOCK"); break;
                case QUIT:      strcpy(statusStr, "QUIT"); break;
                default:        sprintf(statusStr, "%d", processTable[i].status);
            }

            console_output(debugFlag, "%-5d %-7d %-10d %-12s %-6d %-8d %s\n",
                          processTable[i].pid,
                          processTable[i].pParent ? processTable[i].pParent->pid : -1,
                          processTable[i].priority,
                          statusStr,
                          processTable[i].numChildren,
                          processTable[i].cpuTime,
                          processTable[i].name);
        }
    }
}

/*
 * watchdog()
 * 
 * The watchdog process runs at the lowest priority.
 * It ensures the kernel terminates cleanly when all other processes are done.
 */
static int watchdog(char* dummy)
{
    DebugConsole("watchdog(): started\n");

    while (1)
    {
        check_deadlock();
    }

    return 0;
}

/*
 * check_deadlock()
 * 
 * Checks if the system has deadlocked or should terminate.
 * Accounts for processes that may be blocked in WAIT_BLOCK status (waiting for children).
 */
static void check_deadlock()
{
    int i;
    int activeProcesses = 0;

    /* Count processes that are not empty and not watchdog or SchedulerEntryPoint */
    for (i = 0; i < MAX_PROCESSES; i++)
    {
        if (processTable[i].status != EMPTY && processTable[i].status != QUIT)
        {
            if (i != 0)  /* Skip watchdog (usually at index 0) */
            {
                activeProcesses++;
            }
        }
    }

    /* If only watchdog is left, shut down gracefully */
    if (activeProcesses == 1)
    {
        console_output(debugFlag, "watchdog(): No remaining processes. Shutting down.\n");
        stop(0);
    }

    /* Check for deadlock: watchdog running but other processes exist and none ready */
    if (activeProcesses > 1)
    {
        int readyProcesses = 0;
        int runningProcesses = 0;

        for (i = 0; i < MAX_PROCESSES; i++)
        {
            if (processTable[i].status == READY)
                readyProcesses++;
            if (processTable[i].status == RUNNING)
                runningProcesses++;
        }

        /* Deadlock only if processes exist but none are ready or running (not blocked) */
        if (readyProcesses == 0 && runningProcesses == 0)
        {
            console_output(debugFlag, "watchdog(): Deadlock detected! Halting.\n");
            stop(1);
        }
    }
}

/*
 * DebugConsole()
 * 
 * Outputs debug messages if debug flag is enabled.
 */
static void DebugConsole(char* format, ...)
{
    char buffer[2048];
    va_list argptr;

    if (debugFlag)
    {
        va_start(argptr, format);
        vsprintf(buffer, format, argptr);
        console_output(TRUE, buffer);
        va_end(argptr);
    }
}

/*
 * check_io_scheduler()
 * 
 * Placeholder for I/O checking in the scheduler.
 * Currently returns 0 since there is no I/O in this iteration.
 */
int check_io_scheduler()
{
    return 0;
}
