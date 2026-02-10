#define _CRT_SECURE_NO_WARNINGS
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
static void DebugConsole(char* format, ...);
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
    Process *pParent;// we can use this variable to keep track of the parent process if there is one, but it's not strictly necessary since we can always access the parent through the runningProcess variable if needed

    DebugConsole("spawn(): creating process %s\n", name);

    disableInterrupts();

    /* Validate all of the parameters, starting with the name. */
    if (name == NULL || entryPoint == NULL)// if the name or entry point is NULL, we cannot create the process, so return -1 to indicate an error
    {
        console_output(debugFlag, "spawn(): Name value is NULL.\n");
        return -1;
    }
    if (strlen(name) >= (MAXNAME - 1))// if the name is too long, we cannot create the process, so stop the system since this is a critical error that should not happen in normal operation
    {
        console_output(debugFlag, "spawn(): Process name is too long.  Halting...\n");
        stop(1);
    }
    if (stacksize < THREADS_MIN_STACK_SIZE)// if the stack size is too small, we cannot create the process, so stop the system since this is a critical error that should not happen in normal operation
        {
		console_output(debugFlag, "spawn(): Stack size is too small.  Halting...\n");
		stop(1);// if the stack size is too small, we cannot create the process, so stop the system
	}
    if (priority < LOWEST_PRIORITY || priority > HIGHEST_PRIORITY)
    {
        enable_interrupts();
        return -3; // if the priority is invalid, return -3 to indicate an error
    }
    /*Testing for kernel mode*/
    unsigned int psr = get_psr();
    if ((psr & PSR_KERNEL_MODE) == 0)
    {
        console_output(debugFlag, "spawn(): Kernel mode is required. \n");
        return -1;
    }

    /*entrypoint validation*/
    proc_slot = findEmptyProcessSlot();
    if(proc_slot<0)
    {
        enable_interrupts();
        return -4; // if there are no empty slots in the process table, return -4 to indicate that we cannot create a new process
    }
    
    //initialiZe the new process slot in the process table
    pNewProc = &processTable[proc_slot];// get a pointer to the new process slot in the process table
    pNewProc->pid = nextPid++;// assign a unique pid to the new process and increment the nextPid counter for the next process that will be created
    pNewProc->status = STATUS_READY;// set the initial status of the new process to ready
    pNewProc->priority = clamp_priority(priority);// set the priority of the new process to the value passed in as a parameter, but clamp it to the valid range of priorities
    pNewProc->entryPoint = entryPoint;// set the entry point of the new process to the function pointer passed in as a parameter
    pNewProc->stacksize = stacksize;// set the stack size of the new process to the value passed in as a parameter
    pNewProc->exitCode = 0;// initialize the exit code of the new process to 0
    pNewProc->signaled = 0;
    pNewProc->numChildren = 0; // initialize the number of children of the new process to 0
    pNewProc->startTime = system_clock() * 1000; // set the start time to the current system clock time in milliseconds
    pNewProc->cpuTime = 0; // initialize the CPU time used by the new process to 0
    pNewProc->lastDispatchTime = 0; // initialize the last dispatch time to 0
    pNewProc->nextReadyProcess = NULL; // initialize the next ready process pointer to NULL since this process is not yet in the ready queue            

    
   

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
    enable_interrupts();
    DebugConsole("k_spawn(): process %s (pid %d) created with priority %d and stack size %d\n", name, pNewProc->pid, pNewProc->priority, pNewProc->stacksize);
    //Initialize context for this process, but use launch function pointer for
     // the initial value of the process's program counter (PC)
    
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

    // We are now running in the context of the new process, so we can call the function that was passed in as the entry point for this process.  We will also pass in the arguments that were passed to k_spawn as the argument to the entry point function.
    clamp_priority(runningProcess->priority); // make sure the priority is clamped to the valid range before we start running the process, just in case it was changed after the process was created but before it was launched
    SchedulerEntryPoint(args);

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
int  k_wait(int* pChildExitCode)
{
    Process *child;
    int childPid =-1;
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

    child = runningProcess->pChildren; // get the head of the child list
    while( child != NULL)
	{
        if (child->status == STATUS_QUIT)
        {
            *pChildExitCode = child->exitCode; // set the output parameter to the child's exit code
            childPid = child->pid; // get the child's pid to return later
            // remove the child from the list of children
            if (child == runningProcess->pChildren) // if the child is the head of the list, update the head pointer
            {
                runningProcess->pChildren = child->nextSiblingProcess;
            }
            else // otherwise, find the previous sibling and update its next pointer
            {
                Process* prevSibling = runningProcess->pChildren;
                while (prevSibling != NULL && prevSibling->nextSiblingProcess != child)
                {
                    prevSibling = prevSibling->nextSiblingProcess;
                }
                if (prevSibling != NULL)
                {
                    prevSibling->nextSiblingProcess = child->nextSiblingProcess;
                }
            }
            child->status = STATUS_EMPTY; // mark the child process slot as empty in the process table
            child->pid = -1; // reset the child's pid to -1 to indicate that it's no longer a valid process
            enable_interrupts();
            return childPid; // return the pid of the quitting child

        }
	
		child = child->nextSiblingProcess; // move to the next sibling in the list
	}
    enable_interrupts();
    return -1; // if we get here, it means there are no children that have quit, so return -1 to indicate that the parent should block and wait for a child to quit


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
    Process *parent;
    //test for if need to be new process Process *pParent; 
   // Process *pChildren;
    
    disableInterrupts();

    if (runningProcess == NULL)
    {
        enable_interrupts();
        return;
    }

    if (runningProcess->numChildren > 0)
    {
        console_output(debugFlag, "k_exit(): Process %d has %d children.  Cannot exit until all children have exited.\n", runningProcess->pid, runningProcess->numChildren);
        enable_interrupts();
        stop(1);
    }
    if (runningProcess->signaled)
    {
        runningProcess->exitCode = -5; // set the exit code to -5 to indicate that the process was signaled to quit
        runningProcess->status = STATUS_QUIT; // set the process status to quit


        parent = runningProcess->pParent;
        if (parent != NULL)
        {
            parent->numChildren--; // decrement the parent's child count
            if (parent->status == STATUS_BLOCKED)
            {
                parent->status = STATUS_READY; // unblock the parent if it was waiting for this child to exit
                readyq_push(parent);
            }
        }
        DebugConsole("k_exit(): Process %d was signaled to quit. Exiting with code -5.\n", runningProcess->pid);
        runningProcess = NULL; // set the running process to NULL since this process is exiting
        enable_interrupts();
        dispatcher(); // call the dispatcher to switch to another process since this process is exiting
    }
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

    if (pChildExitCode == NULL)
    {
        return-1;
    }
    disableInterrupts();
    if (runningProcess == NULL)
    {
        enable_interrupts();
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
    if (targetProcess == runningProcess->pParent)
    {
        console_output(debugFlag, "k_join(): A process cannot join on its parent.\n");
        stop(2);
    }
    while (&targetProcess->status != STATUS_QUIT)
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
    if (blockStatus <=10) // we can define some block status codes if we want, but for now just check that it's a valid value
	{
		console_output(debugFlag, "block(): Invalid block status value.\n");
        stop(1); 
	}
	if(runningProcess == NULL)// if there is no running process, we cannot block, so return -1 to indicate an error
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

    for(i = 0; i <  MAX_PROCESSES; i++)
    {
            if(processTable[i].status != STATUS_EMPTY) // only display processes that are not empty
			{
				switch(processTable[i].status) // convert the status code to a string for display
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
    int currentTime = 0;
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
    if (activeProcesses > 1)
    {
        int readyProcesses = 0;
        int runningProcesses = 0;
        for (i = 0; i < MAXPROC; i++)
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

    if (runningProcess == NULL)
		return;
    currentTime = read_clock();
	runningProcess->cpuTime += (currentTime - runningProcess->lastDispatchTime);
	runningProcess->lastDispatchTime = currentTime;

	if (runningProcess->cpuTime >= 80)
	{
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
  nextPid=1; // start at 1 since 0 is reserved for the null process
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