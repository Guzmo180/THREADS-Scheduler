#define _CRT_SECURE_NO_WARNINGS
#define NUM_PRIORITIES 6
#define MAXPROC 51
#include <stdio.h>
#include "THREADSLib.h"
#include "Scheduler.h"
#include "Processes.h"

void readyq_push(Process* proc);  //fixed the 2371 error
Process* readyq_pop_highest(void);
Process* readyProcs[NUM_PRIORITIES];
Process processTable[MAXPROC];
Process* runningProcess = NULL;
int nextPid = 1;
int debugFlag = 1;

static int watchdog(char*);
static inline void disableInterrupts();
static inline void enable_interrupts();
static int clamp_priority(int priority);
void dispatcher();
static int launch(void*);
static void check_deadlock();
static void DebugConsole(char* format, ...);


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
        Procestable[i].signaled = 0;
        processTable[i].cputime = 0;
        processTable[i].startTime = 0;
        processTable[i].lastdispatchTime = 0;
        }
            //  COWBOYS FOR LIFE!!!!!       
            // point to head of ready queue need to initialize the ready queue as well
          
             
         
            nextPid=1; // start at 1 since 0 is reserved for the null process




    /* Initialize the Ready list, etc. */
    for (int i = 0; i < NUM_PRIORITIES; i++)
    {
        readyProcs[i] = NULL;
    }
    //readyProcs[0] = NULL;

    /* Initialize the clock interrupt handler */
    interrupt_handler_t* handlers;
    handlers = get_interrupt_handlers();
    //handlers[THREADS_TIMER_INTERRUPT] = time_slice;


    /* startup a watchdog process */
    result = k_spawn("watchdog", watchdog, NULL, THREADS_MIN_STACK_SIZE, LOWEST_PRIORITY);
    if (result < 0)
    {
        console_output(debugFlag, "Scheduler(): spawn for watchdog returned an error (%d), stopping...\n", result);
        stop(1);
    }

    /* start the test process, which is the main for each test program.  */
    result = k_spawn("Scheduler", SchedulerEntryPoint, NULL, 2 * THREADS_MIN_STACK_SIZE, HIGHEST_PRIORITY);
    if (result < 0)
    {
        console_output(debugFlag, "Scheduler(): spawn for SchedulerEntryPoint returned an error (%d), stopping...\n", result);
        stop(1);
    }
    enable_interrupts();
    dispatcher();
    //printf("%c is result", result);

    /* Initialized and ready to go!! */

    /* This should never return since we are not a real process. */

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

    DebugConsole("spawn(): creating process %s\n", name);

    disableInterrupts();

    /* Validate all of the parameters, starting with the name. */
    if (name == NULL)
    {
        console_output(debugFlag, "spawn(): Name value is NULL.\n");
        return -1;
    }
    if (strlen(name) >= (MAXNAME - 1))
    {
        console_output(debugFlag, "spawn(): Process name is too long.  Halting...\n");
        stop(1);
    }


    /*Testing for kernel mode*/
    unsigned int psr = get_psr();
    if ((psr & PSR_KERNEL_MODE) == 0)
    {
        console_output(debugFlag, "spawn(): Kernel mode is required. \n");
        return -1;
    }

    /*entrypoint validation*/
    if (entryPoint == NULL)
    {
        console_output(debugFlag, "spawn(): Entry point value is NULL.\n");
        return -1;
    }
    /*Checking stack size and priorities*/
    if (stacksize < THREADS_MIN_STACK_SIZE)
    {
        console_output(debugFlag, "spawn():  Stack size is to small.\n");
        return -1;
    }
    if (priority < LOWEST_PRIORITY || priority > HIGHEST_PRIORITY)
    {
        console_output(debugFlag, "spawn():  Priority value is invalid.\n");
        return -1;
    }
    /* Find an empty slot in the process table */

    //proc_slot = -1;  // just use 1 for now! needs to be -1

    //int checkedSlots = 0;
    //int procSlotIndex = 0;
    for (int i = 0; i < MAXPROC; i++)
    {
        if (processTable[i].status == STATUS_EMPTY)
        {
            proc_slot = i;
            break;  //so it stops looking
        }
    }
    if (proc_slot == -1)
    {
        console_output(debugFlag, "spawn(): no process slots free. \n");
        return -1;
    }
    pNewProc = &processTable[proc_slot];

    /* Setup the entry in the process table. */
    strcpy(pNewProc->name, name);
    pNewProc->pid = nextPid++;
    pNewProc->status = STATUS_READY;
    pNewProc->priority = clamp_priority(priority);
    pNewProc->entryPoint = entryPoint;

    /* If there is a parent process,add this to the list of children. */
    if (runningProcess != NULL)
    {
        pNewProc->pParent = runningProcess;
    }
    //next sib and pchild logic maybe here
    else
    {
        pNewProc->pParent = NULL;
    }

    /* Add the process to the ready list. */
    readyq_push(pNewProc);

    /* Initialize context for this process, but use launch function pointer for
     * the initial value of the process's program counter (PC)
    */
    pNewProc->context = context_initialize(launch, stacksize, arg);

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

    DebugConsole("launch(): started: %s\n", runningProcess->name);

    /* Enable interrupts */
    enable_interrupts();

    //call the function passed to k_spawn
    int result = runningProcess->entryPoint(args);
    /* Call the function passed to spawn and capture its return value */
    DebugConsole("Process %d returned to launch\n", runningProcess->pid);

    /* Stop the process gracefully */
    k_exit(result);
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
int k_wait(int* code)
{
    disableInterrupts();
    runningProcess->status = STATUS_BLOCKED;
    dispatcher();
    return 0;

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
    disableInterrupts();
    runningProcess->status = STATUS_QUIT;
    
    if (runningProcess->pParent != NULL)
    {
        if (runningProcess->pParent->status == STATUS_BLOCKED)
        {
            runningProcess->pParent->status = STATUS_READY;
            readyq_push(runningProcess->pParent);
        }
    }
   
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
    Process* targerProcess;

    disableInterrupts();

    if(signal != SIG_TERM)
	{
		console_output(debugFlag, "k_kill(): Invalid signal value.\n");
		return -1;
	}   
    //FIND THE TARGET PROCESS
    targerProcess = readyq_remove_pid(pid);
    if( targerProcess == NULL)
	{
		console_output(debugFlag, "k_kill(): No process with pid %d found.\n", pid);
		return -1;
	}
    targerProcess->signaled = 1; // set the signaled flag for the target process

	if (targerProcess->status == STATUS_BLOCKED)
	{
		targerProcess->status = STATUS_READY;
		readyq_push(targerProcess);
	}
    return 0;
}

/**************************************************************************
   Name - k_getpid
*************************************************************************/
int k_getpid()
{	if (runningProcess == NULL)
        return -1;
	return runningProcess->pid;

}

/**************************************************************************
   Name - k_join
***************************************************************************/
int k_join(int pid, int* pChildExitCode)
{
    Process* targetProcess;

    if (pchildExitCode == NULL)
    {
        return-1;
    }
    disableInterrupts();    
    if (runningProcess==NULL)
    {
		ENableInterrupts();
		return -1;
	}
    if (pid = runningProcess->pid)
    {
        console_output(debugFlag, "k_join(): A process cannot join on itself.\n");
        stop(1);
    }

    targetProcess = readyq_remove_pid(pid);
	if (targetProcess == NULL)
	{
		console_output(debugFlag, "k_join(): No process with pid %d found.\n", pid);
		enable_interrupts();
        stop(1);
	}
    if( targetProcess == runningProcess->pParent)
    {
        console_output(debugFlag, "k_join(): A process cannot join on its parent.\n");
		stop(2);
	}
    while (targetProcess->status != STATUS_QUIT)
    {
        enable_interrupts();
        disableInterrupts();

        if (runningProcess->signaled)
        {
            enable_interrupts();
            return -5;
        }
        targetProcess = readyq_remove_pid(pid);
        if (targetProcess == NULL)
        {
            enable_interrupts();
            return 0;
        }
    }
        *pChildExitCode = targetProcess->exitCode;
        enable_interrupts();    
        return 0;

    
}   

/**************************************************************************
   Name - unblock
*************************************************************************/
int unblock(int pid)
{
    return 0;
}

/*************************************************************************
   Name - block
*************************************************************************/
int block(int newStatus)
{
    return 0;
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
    if( runningProcess == NULL)
		return 0;)
	return runningProcess->cputime;
}

/*************************************************************************
   Name - readClock
*************************************************************************/
DWORD read_clock()
{
    return system_clock();
}

void display_process_table()
{

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

    if(runningProcess != NULL && runningProcess->status == STATUS_RUNNING)
	{
		runningProcess->status = STATUS_READY;
		readyq_push(runningProcess);
	}
    if(readyq_pop_highest == NULL)
    {
        enable_interrupts();
        return;
    }

    nextProcess = readyq_pop_highest();
    if (nextProcess == NULL)
    {
        console_output(debugFlag, "dispatcher(): No ready process found!  Stopping...\n");
        stop(3);
    }

    runningProcess = nextProcess;
    runningProcess->status = STATUS_RUNNING;
    currentTime = read_clock();
    DebugConsole("dispatcher(): switching to process %s (pid %d)\n", runningProcess->name, runningProcess->pid);

    // check the runningproccess time_slice
    //time_slice();
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
    for (i = 0; i < MAXPROC; i++)
	{
		if (processTable[i].status != STATUS_EMPTY && processTable[i].status != STATUS_QUIT)
		{
			activeProcesses++;
		}
	}
    	if (activeProcesses == 1)   
        {
			console_output(debugFlag, "waxhdog(): no remaining processes.  Stopping...\n");
            stop(0);
            }
        if (activeProcesses >1)
        {
            int readyProcesses = 0;
            int runningProcesses = 0;
         for( i = 0; i < MAXPROC; i++)  
             {
             if (processTable[i].status == STATUS_READY)
				{
					readyProcesses++;
				}
				else if (processTable[i].status == STATUS_RUNNING)
				{
					runningProcesses++;
				}
             if (readyProcesses == 0 && runningProcesses == 0)
             {

                 console_output(debugFlag, "watchdog(): deadlock detected.  Stopping...\n");
                 stop(1);
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



static int clamp_priority(int priority)
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

void readyq_push(Process* proc)
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

}