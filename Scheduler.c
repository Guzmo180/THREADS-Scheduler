#define _CRT_SECURE_NO_WARNINGS
#define EMPTY 0
#define NUM_PRIORITIES 6
#include <stdio.h>
#include "THREADSLib.h"
#include "Scheduler.h"
#include "Processes.h"

void readyq_push(Process* proc);  // push a process onto the ready queue based on its priority
Process* readyq_pop_highest(void);// Pop the highest priority process
Process* readyq_remove_pid(int pid);// Remove a process with the specified pid from the ready queue and return it, or return NULL if no such process is found
Process* readyProcs[NUM_PRIORITIES];// array of pointers to the head of the ready queue for each priority level, where index 0 is the lowest priority and index NUM_PRIORITIES-1 is the highest priority
Process processTable[MAXPROC]; // the process table, which is an array of Process structures that holds information about all processes in the system
Process* runningProcess = NULL; // pointer to the currently running process, or NULL if there is no running process
int nextPid = 1;// variable to keep track of the next available process ID, starting at 1 since 0 is reserved for the null process
int debugFlag = 1; // set to 1 to enable debug output, or 0 to disable it

static void initialize_process_table(); // function to initialize the process table by setting all entries to empty and initializing other fields as needed
static int watchdog(char*); // the watchdog process function, which will run in an infinite loop to check for deadlock conditions and keep the system running when all other processes are blocked
static inline void disableInterrupts(); // function to disable interrupts by clearing the appropriate bit in the processor status register (PSR)
static inline void enable_interrupts();//  function to enable interrupts by setting the appropriate bit in the processor status register (PSR)
static int clamp_priority(int priority);// function to clamp a priority value to the valid range of priorities (0 to NUM_PRIORITIES-1)
void dispatcher(); // function to perform a context switch to the next process to run, which is selected from the ready queue based on priority
static int launch(void*);
static void check_deadlock();// function to check for deadlock conditions by counting the number of active processes and checking if there are any ready or running processes
static void DebugConsole(format, ...); // function to print debug messages to the console if the debug flag is enabled, using a format string and variable arguments
static void clock_handler(char* devicename, uint8_t command, uint32_t status); // function to handle clock interrupts by calling the time_slice function to update the CPU time of the running process and perform a context switch if necessary


/* DO NOT REMOVE */
extern int SchedulerEntryPoint(void* pArgs); // the entry point function for the startup process, which will be spawned by the bootstrap function to initialize additional layers of the OS and test the scheduler functions
int check_io_scheduler(); // function to check for pending I/O operations, which is used by the watchdog process to determine if it should check for deadlock conditions or not.  Since there is no I/O in this implementation, it will always return false.
check_io_function check_io; // function pointer that is set to the check_io_scheduler function, which is used by the watchdog process to check for pending I/O operations.  This allows for flexibility in how the watchdog checks for I/O, and allows for future expansion if I/O functionality is added to the system.


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
    dispatcher();// call the dispatcher to start running processes, which will start with the watchdog since it has the lowest priority and was spawned first.  The watchdog will then check for deadlock conditions and keep the system running until the SchedulerEntryPoint process is ready to run, at which point it will be scheduled to run based on its priority.
    

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
    int proc_slot = -1; // variable to hold the index of the empty slot in the process table that we will use for the new process, initialized to -1 to indicate that we haven't found an empty slot yet
    struct _process* pNewProc; // pointer to the new process structure that we will initialize with the information for the new process, which will be stored in the process table at the index found in proc_slot
    Process* pParent;// we can use this variable to keep track of the parent process if there is one, but it's not strictly necessary since we can always access the parent through the runningProcess variable if needed

    DebugConsole("spawn(): creating process %s\n", name);

    disableInterrupts(); //disable interrupts

    /*Validate all of the parameters, starting with the name.*/
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
    if (priority < LOWEST_PRIORITY || priority > HIGHEST_PRIORITY)// if the priority is invalid, we cannot create the process, so return -3 to indicate an error
    {
        enable_interrupts();
        return -3; // if the priority is invalid, return -3 to indicate an error
    }
    /*Testing for kernel mode*/
    unsigned int psr = get_psr(); // get the current value of the processor status register (PSR) to check if we are in kernel mode, since only processes running in kernel mode should be able to create new processes.  If we are not in kernel mode, we cannot create the process, so return -1 to indicate an error.
    if ((psr & PSR_KERNEL_MODE) == 0)
    {
        console_output(debugFlag, "spawn(): Kernel mode is required. \n");
        return -1;
    }

    /*entrypoint validation find empty PCB slot*/
    proc_slot = findEmptyProcessSlot(); // find an empty slot in the process table to use for the new process, which will be indicated by a status of STATUS_EMPTY.  If no empty slot is found, we cannot create the process, so return -4 to indicate that we cannot create a new process due to lack of resources.
    if (proc_slot < 0)
    {
        enable_interrupts();
        return -4; // if there are no empty slots in the process table, return -4 to indicate that we cannot create a new process
    }

    //initialiZe the new process slot in the process table
    pNewProc = &processTable[proc_slot];// get a pointer to the new process slot in the process table
    pNewProc->pid = nextPid++;// assign a unique pid to the new process and increment the nextPid counter for the next process that will be created
    pNewProc->status = STATUS_READY;// set the initial status of the new process to ready

    strncpy(pNewProc->name, name, MAXNAME); // copy the name of the process into the process structure, using strncpy to avoid buffer overflow and ensuring that the name is null-terminated
    pNewProc->name[MAXNAME - 1] = '\0';
    if (arg != NULL)
    {
        strncpy((char*)pNewProc->startArgs, (char*)arg, 255);
        pNewProc->startArgs[255] = '\0';
    }
    else
    {
        pNewProc->startArgs[0] = '\0'; //this makes it empty if no args
    }

    pNewProc->priority = clamp_priority(priority);  //set the priority of the new process to the value passed in as a parameter, but clamp it to the valid range of priorities
    pNewProc->entryPoint = entryPoint;              //set the entry point of the new process to the function pointer passed in as a parameter
    pNewProc->stacksize = stacksize;                //set the stack size of the new process to the value passed in as a parameter
    pNewProc->exitCode = 0;                         //initialize the exit code of the new process to 0
    pNewProc->signaled = 0;
    pNewProc->numChildren = 0;                      //initialize the number of children of the new process to 0
    pNewProc->startTime = system_clock() * 1000;    // set the start time to the current system clock time in milliseconds
    pNewProc->cpuTime = 0;                          //initialize the CPU time used by the new process to 0
    pNewProc->lastDispatchTime = 0;                 // initialize the last dispatch time to 0
    pNewProc->nextReadyProcess = NULL;              // initialize the next ready process pointer to NULL since this process is not yet in the ready queue            



    /*Link child to parent*/
    if (runningProcess != NULL) // if there is a currently running process, we will set that process as the parent of the new process and update the parent's child list and child count accordingly.  If there is no currently running process, we will set the parent pointer of the new process to NULL since it will not have a parent.
    {
        pNewProc->pParent = runningProcess; //go to the struct and access pParent inside that struct &store the address of current running process
        /*at this point our runningProcess is NULL and there should be a running process*/


        /*Insert child at head of parent's child list */
        pNewProc->nextSiblingProcess = runningProcess->pChildren;
        runningProcess->pChildren = pNewProc;

        /*Increment child count*/
        runningProcess->numChildren++;// increment the child count of the parent process to reflect the creation of the new child process
    }
    else
    {
        pNewProc->pParent = NULL; // if there is no currently running process, set the parent pointer of the new process to NULL since it will not have a parent
    }

    /* Add the process to the ready list. */
    readyq_push(pNewProc); // add the new process to the ready queue based on its priority, which will make it eligible to be scheduled to run by the dispatcher when it's its turn based on its priority and the scheduling algorithm used by the dispatcher
    enable_interrupts(); // enable interrupts after we have finished modifying the process table and ready queue to allow the system to continue handling interrupts and scheduling processes as needed
    DebugConsole("k_spawn(): process %s (pid %d) created with priority %d and stack size %d\n", name, pNewProc->pid, pNewProc->priority, pNewProc->stacksize);// print a debug message to the console with information about the new process that was created, including its name, pid, priority, and stack size
    //Initialize context for this process, but use launch function pointer for


    pNewProc->context = context_initialize(launch, stacksize, arg);

    return pNewProc->pid; // return the pid of the new process to indicate success


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
    //SchedulerEntryPoint(args);

    //call the function passed to k_spawn
    int result = runningProcess->entryPoint(runningProcess->startArgs); // call the entry point function for this process, passing in the start arguments that were set when the process was created.  The result of this function call will be used as the exit code when the process exits
    /* Call the function passed to spawn and capture its return value */
    DebugConsole("Process %d returned to launch\n", runningProcess->pid); // print a debug message to the console indicating that the process has returned from its entry point function and is now exiting, along with the pid of the process

    /* Stop the process gracefully */
    k_exit(result); // call k_exit with the result of the entry point function as the exit code, which will allow the parent process to retrieve this exit code when it waits for this process to exit.  This will also ensure that the process is cleaned up properly and that any resources it was using are released.
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
    Process* child; // variable to keep track of the child process that we are currently checking in the list of children of the running process, which we will use to check if any child has already quit before we decide to block the parent process and wait for a child to quit.  If we find a child that has already quit 
    if (pChildExitCode == NULL)// if the output parameter for the child's exit code is NULL, we cannot return the exit code of the child process, so return -1 to indicate an error
    {
        return -1;
    }
    disableInterrupts();
    if (runningProcess == NULL)// if there is no currently running process, we cannot wait for a child process to quit, so return -1 to indicate an error
    {
        enable_interrupts();
        return -1;
    }

    child = runningProcess->pChildren; // get the head of the list of children of the running process to start checking if any child has already quit before we decide to block the parent process and wait for a child to quit
    while (child != NULL)
    {
        if (child->status == STATUS_QUIT)
        {
            *pChildExitCode = child->exitCode; // set the output parameter to the child's exit code
            int childPid = child->pid;
            //childPid = child->pid; // get the child's pid to return later
            //remove the child from the list of children
            if (child == runningProcess->pChildren) // if the child is the head of the list, update the head pointer
            {
                runningProcess->pChildren = child->nextSiblingProcess;// update the head of the list of children to point to the next sibling process, effectively removing the child from the list
            }
            else //otherwise, find the previous sibling and update its next pointer
            {
                Process* prevSibling = runningProcess->pChildren; // start at the head of the list of children to find the previous sibling of the child that we want to remove
                while (prevSibling != NULL && prevSibling->nextSiblingProcess != child)// loop through the list of children until we find the previous sibling of the child that we want to remove, which is the sibling whose nextSiblingProcess pointer points to the child we want to remove. 
                {
                    prevSibling = prevSibling->nextSiblingProcess;// move to the next sibling in the list to continue searching for the previous sibling of the child we want to remove
                }
                if (prevSibling != NULL)// if we found the previous sibling, update its nextSiblingProcess pointer to skip over the child we are removing and point to the next sibling after the child, effectively removing the child from the list of children
                {
                    prevSibling->nextSiblingProcess = child->nextSiblingProcess;
                }
            }
            child->status = STATUS_EMPTY; //mark the child process slot as empty in the process table
            child->pid = -1; //reset the child's pid to -1 to indicate that it's no longer a valid process
            enable_interrupts();
            return childPid; //return the pid of the quitting child

        }

        child = child->nextSiblingProcess; // move to the next sibling in the list
    }

    //No child has quit so we can block the parent
    runningProcess->status = STATUS_BLOCKED;
    enable_interrupts();
    dispatcher();

    //When we resume, a child has exited
    //Search again for the child that quit
    disableInterrupts();
    child = runningProcess->pChildren;// start at the head of the list of children again to find the child that has quit while we were blocked, which should be the reason we were unblocked and resumed by the dispatcher.  We will loop through the list of children again to find the child that has quit, set the output parameter to its exit code, and return its pid.  
    while (child != NULL)// loop through the list of children again to find the child that has quit while we were blocked, which should be the reason we were unblocked and resumed by the dispatcher.  If we find such a child, we will set the output parameter to its exit code and return its pid.  .
    {
        if (child->status == STATUS_QUIT)
        {
            *pChildExitCode = child->exitCode;// set the output parameter to the child's exit code
            int childPid = child->pid;// get the child's pid to return later

            //unlink child from sibling list
            if (child == runningProcess->pChildren)
                runningProcess->pChildren = child->nextSiblingProcess; // if the child that quit is the head of the list of children, update the head pointer to point to the next sibling process, effectively removing the child from the list
            else {
                Process* prev = runningProcess->pChildren;// if the child that quit is not the head of the list of children, we need to find the previous sibling in the list and update its nextSiblingProcess pointer to skip over the child that quit and point to the next sibling after it, effectively removing the child from the list
                while (prev->nextSiblingProcess != child)// loop through the list of children until we find the previous sibling of the child that quit, which is the sibling whose nextSiblingProcess pointer points to the child that quit.  
                    prev = prev->nextSiblingProcess;// move to the next sibling in the list to continue searching for the previous sibling of the child that quit
                prev->nextSiblingProcess = child->nextSiblingProcess;// update the nextSiblingProcess pointer of the previous sibling to skip over the child that quit and point to the next sibling after it, effectively removing the child that quit from the list of children
            }

            child->status = STATUS_EMPTY; // mark the child process slot as empty in the process table to indicate that it's no longer a valid process
            child->pid = -1; // reset the child's pid to -1 to indicate that it's no longer a valid process

            enable_interrupts(); // enable interrupts before returning since we disabled them at the start of the function
            return childPid; // return the pid of the child that quit to indicate success
        }
        child = child->nextSiblingProcess; // move to the next sibling in the list to continue searching for the child that quit
    }

    enable_interrupts();
    return -1;   // should not happen unless logic elsewhere is broken
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
    Process* parent; // variable to keep track of the parent process of the currently running process, which we will need to update when the current process exits to decrement the parent's child count and potentially unblock the parent if it was waiting for this child to exit.  We will also need to set the exit code and status of the current process to indicate that it has exited, and then call the dispatcher to switch to another process since the current process is exiting.  If there is no parent process (i.e., this is a root process), we will just set the exit code and status and call the dispatcher without worrying about updating a parent process.
    //test for if need to be new process Process *pParent; 


    disableInterrupts(); 

    if (runningProcess == NULL) // if there is no currently running process, we cannot exit since there is no process to exit, so just enable interrupts and return without doing anything
    {
        enable_interrupts();
        return;
    }

    if (runningProcess->numChildren > 0)// if the currently running process has any children that have not yet exited, we cannot exit this process until all of its children have exited
    {
        console_output(debugFlag, "k_exit(): Process %d has %d children.  Cannot exit until all children have exited.\n", runningProcess->pid, runningProcess->numChildren);
        enable_interrupts();
        stop(1);// if there are still children that have not exited, stop the system since this is a critical error that should not happen in normal operation
    }
    if (runningProcess->signaled) // if the currently running process has been signaled to quit (e.g., by k_kill), we will set the exit code to -5 to indicate that the process was signaled to quit, and then set the status to STATUS_QUIT to indicate that the process is exiting due to being signaled. 
    {
        runningProcess->exitCode = -5; // set the exit code to -5 to indicate that the process was signaled to quit
        runningProcess->status = STATUS_QUIT; // set the process status to quit


        parent = runningProcess->pParent; // get the parent process of the currently running process to update its child count and potentially unblock it if it was waiting for this child to exit.  
        if (parent != NULL) // if there is a parent process, we need to update its child count and potentially unblock it if it was waiting for this child to exit, since the current process is exiting due to being signaled to quit. 
        {
            parent->numChildren--; // decrement the parent's child count
            if (parent->status == STATUS_BLOCKED)//check to see if the parent current status is blocked
            {
                parent->status = STATUS_READY; // unblock the parent if it was waiting for this child to exit
                readyq_push(parent); // add the parent back to the ready queue since it is now ready to run after being unblocked
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
    Process* targetProcess; //variable to keep track of the target process that we want to signal 

    disableInterrupts();

    if (signal != SIG_TERM) //if signal is not a valid signal we will call the definition to kill the process and return error code -1 to indicate that the signal value is invalid, since we only have one signal defined for this system (SIG_TERM) which is used to signal a process to terminate.
    {
        console_output(debugFlag, "k_kill(): Invalid signal value.\n");
        return -1;
    }
    //FIND THE TARGET PROCESS
    targetProcess = readyq_remove_pid(pid); // find the target process with the specified pid in the ready queue and remove it from the ready queue if it's there, which will allow us to update its status and potentially unblock it if it's currently blocked. 
    if (targetProcess == NULL)
    {
        console_output(debugFlag, "k_kill(): No process with pid %d found.\n", pid);
        return -1;
    }
    targetProcess->signaled = 1; // set the signaled flag for the target process

    if (targetProcess->status == STATUS_BLOCKED)// if the target process is currently blocked, we will unblock it by setting its status to STATUS_READY and adding it back to the ready queue
    {
        targetProcess->status = STATUS_READY;// set the status of the target process to ready to unblock it if it was waiting for something
        readyq_push(targetProcess);
    }
    return 0;
}

/**************************************************************************
   Name - k_getpid
*************************************************************************/
int k_getpid()
{
    if (runningProcess == NULL) // if there is no currently running process, we cannot return a valid pid, so return -1 to indicate an error
    {
        return -1;
    }
    return runningProcess->pid; // return the pid of the currently running process to indicate success

}

/**************************************************************************
   Name - k_join
***************************************************************************/
int k_join(int pid, int* pChildExitCode)
{
    Process* targetProcess;// varible to keep track ofthe join taget process that will be joined, which is the process with the specified pid that we want to wait for to exit and retrieve its exit code.  


    if (pChildExitCode == NULL)// if the output parameter for the child's exit code is NULL, we cannot return the exit code of the child process return -1 to indicate an error
    {
        return-1;
    }
    disableInterrupts();
    if (runningProcess == NULL)// if there is no currently running process, we cannot join on a child process
    {
        enable_interrupts();
        return -1; // if there is no currently running process, return -1 to indicate an error since we cannot join on a child process if there is no parent process that is currently running
    }
    if (pid == runningProcess->pid)  // if the specified pid is the same as the pid of the currently running process, we cannot join on ourselves, so stop the system since this is a critical error that should not happen in normal operation
    {
        console_output(debugFlag, "k_join(): A process cannot join on itself.\n");
        stop(1);
    }

    targetProcess = readyq_remove_pid(pid); // find the target process with the specified pid in the ready queue and remove it from the ready queue if it's there, which will allow us to check its status and potentially block the parent process if the target process has not yet exited. 
    if (targetProcess == NULL) // if we cannot find a process with the specified pid in the ready queue, it means that there is no such process that we can join on, so we will stop the system since this is a critical error that should not happen in normal operation.  
    {
        console_output(debugFlag, "k_join(): No process with pid %d found.\n", pid);
        enable_interrupts();
        stop(1);
    }
    if (targetProcess == runningProcess->pParent) // if the target process that we want to join on is the parent of the currently running process, we cannot join on our parent since that would create a circular dependency and potential deadlock
    {
        console_output(debugFlag, "k_join(): A process cannot join on its parent.\n");
        stop(2);
    }
    while (&targetProcess->status != STATUS_QUIT) // if the target process has not yet exited  we will block the currently running process and wait for the target process to exit.  
    {
        enable_interrupts();
        disableInterrupts();

        if (runningProcess->signaled) // if the currently running process has been signaled to quit while we were waiting for the target process to exit, 
        {
            enable_interrupts();
            return -5; //return -5 to indicate that the join was interrupted by a signal to quit
        }
        targetProcess = readyq_remove_pid(pid); // check the ready queue again to see if the target process has exited while we were waiting
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
    return runningProcess->cpuTime;// return the CPU time used by the currently running process, which is stored in the process structure and updated by the time slice interrupt handler to keep track of how much CPU time each process has used. 
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
    Process* nextProcess = readyq_pop_highest(); // get the next process to run from the ready queue based on the scheduling algorithm used by the dispatcher, which in this case is a priority-based scheduling algorithm that pops the highest priority process from the ready queue. 

    if (runningProcess != NULL && runningProcess->status == STATUS_RUNNING) // if there is a currently running process and its status is still running (i.e., it has not been blocked or quit), we will set its status back to ready and add it back to the ready queue since it is still eligible to run and should be scheduled again by the dispatcher when it's its turn based on its priority and the scheduling algorithm used by the dispatcher.
    {
        runningProcess->status = STATUS_READY; // set the status of the currently running process back to ready 
        readyq_push(runningProcess); // add the currently running process back to the ready queue since it is still eligible to run 
    }


    
    if (nextProcess == NULL) // if there are no ready processes in the ready queue, we cannot dispatch to any process, so we will stop the system since this is a critical error that should not happen in normal operation. 
    {
        console_output(debugFlag, "dispatcher(): No ready process found!  Stopping...\n");
        stop(3);
    }
    int currentTime = 0;
    runningProcess = nextProcess; // set the next process to run as the currently running process
    runningProcess->status = STATUS_RUNNING;
    currentTime = read_clock();// read the current time from the system clock to update the last dispatch time for the running process, which can be used by the time slice interrupt handler to determine how much CPU time the process has used since it was last dispatched and when it should be preempted if it has used up its time slice.
    DebugConsole("dispatcher(): switching to process %s (pid %d)\n", runningProcess->name, runningProcess->pid);

    
    context_switch(runningProcess->context); // perform the context switch to the next process, which will save the state of the currently running process and restore the state of the next process so that it can start running. 

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
        if (processTable[i].status != STATUS_EMPTY && processTable[i].status != STATUS_QUIT)// if the process slot is not empty and the process has not quit, it means that there is an active process in the system, so we will increment the count of active processes.  
        {
            activeProcesses++;
        }
    }
    if (activeProcesses == 1) // if there is only one active process in the system, it means that there are no other processes that can run and the system is effectively idle, so we will stop the system since there are no remaining processes to run and the system is effectively shut down.
    {
        console_output(debugFlag, "waxhdog(): no remaining processes.  Stopping...\n");
        stop(0);
    }
    if (activeProcesses > 1) // if there is more than one active process in the system, it means that there are processes that are still running or ready to run, so we will check for a potential deadlock condition by counting the number of processes that are in the ready state and the number of processes that are in the running state.  If there are no processes in either the ready or running state, it means that all active processes are blocked and there is a deadlock condition, so we will stop the system since this is a critical error that should not happen in normal operation.
    {
        int readyProcesses = 0;
        int runningProcesses = 0;
        for (i = 0; i < MAXPROC; i++)
        {
            if (processTable[i].status == STATUS_READY)// if the process is in the ready state, we will increment the count of ready processes since it means that there is a process that is ready to run and can be scheduled by the dispatcher when it's its turn based on its priority and the scheduling algorithm used by the dispatcher.
            {
                readyProcesses++;
            }
            else if (processTable[i].status == STATUS_RUNNING)// if the process is in the running state, we will increment the count of running processes since it means that there is a process that is currently running and using the CPU, which can also indicate that there are processes that are still active and not blocked.
            {
                runningProcesses++;
            }
            if (readyProcesses == 0 && runningProcesses == 0)// if there are no processes in either the ready or running state, it means that all active processes are blocked and there is a deadlock condition, so we will stop the system since this is a critical error that should not happen in normal operation.
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
    if (priority < 0) // if the priority is less than 0, we will clamp it to 0 since that is the lowest valid priority value in our system. 
    {
        return 0;
    }
    if (priority >= NUM_PRIORITIES) // if the priority is greater than or equal to the number of priorities defined in our system
    {
        return NUM_PRIORITIES - 1;

    }
    return priority;

}

void readyq_push(Process* proc) // push a process onto the ready queue based on its priority
{
    if (proc == NULL) return;
    int prio = clamp_priority(proc->priority); // clamp the priority of the process to ensure that it is within the valid range of priorities defined in our system
    proc->nextReadyProcess = NULL;
    if (readyProcs[prio] == NULL)  // if there are no processes currently in the ready queue for this priority level, we will set the head of the ready queue for this priority level to point to the new process since it will be the only process in the ready queue for this priority level.  
    {
        readyProcs[prio] = proc; // set the head of the ready queue for this priority level to point to the new process since it will be the only process in the ready queue for this priority level
        
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
    prio = clamp_priority(prio); // clamp the priority to ensure that it is within the valid range of priorities defined in our system before we try to pop a process from the ready queue for this priority level.
    Process* head = readyProcs[prio];
    if (head == NULL) return NULL; // if there are no processes in the ready queue for this priority level, return NULL to indicate that there are no processes to pop
    readyProcs[prio] = head->nextReadyProcess; // update the head of the ready queue for this priority level to point to the next process in the ready queue, effectively removing the head process from the ready queue for this priority level.
    head->nextReadyProcess = NULL; // set the nextReadyProcess pointer of the popped process to NULL to indicate that it is no longer in the ready queue and to prevent any potential issues with dangling pointers 
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

    while (cur != NULL) // loop through the ready queue for the priority level of the target process to find the process with the specified pid and remove it from the ready queue if it's there, which will allow us to update its status and potentially unblock it if it's currently blocked.
    {
        if (cur == target) // if we found the target process with the specified pid in the ready queue for its priority level
        {
            if (prev == NULL)
            {
                readyProcs[prio] = cur->nextReadyProcess;// if the target process is the head of the ready queue for its priority level
            }

            else {
                prev->nextReadyProcess = cur->nextReadyProcess; // if the target process is not the head of the ready queue for its priority level
            }

            cur->nextReadyProcess = NULL; // set the nextReadyProcess pointer of the removed process to NULL to indicate that it is no longer in the ready queue and to prevent any potential issues with dangling pointers
            return cur;
        }
        prev = cur;
        cur = cur->nextReadyProcess; // move to the next process in the ready queue for the target process's priority level to continue searching for the target process with the specified pid
    }
    return NULL;
}

void time_slice(void)
{
    uint32_t currentTime; // variable to keep track of the current time read from the system clock

    if (runningProcess == NULL) // if there is no currently running process, we cannot update its CPU time or check for time slice expiration, so just
        return;
    currentTime = read_clock(); // read the current time from the system clock to calculate how much CPU time the currently running process has used since it was last dispatched
    runningProcess->cpuTime += (currentTime - runningProcess->lastDispatchTime); // update the CPU time used by the currently running process by adding the time elapsed since it was last dispatched, which is calculated as the difference between the current time and the last dispatch time stored in the process structure for the currently running process. 
    runningProcess->lastDispatchTime = currentTime; // update the last dispatch time for the currently running process to the current time so that we can calculate the CPU time used by the process in the next time slice interrupt handler invocation.

    if (runningProcess->cpuTime >= 80) // if the currently running process has used up its time slice (e.g., 80 milliseconds), we will preempt it by calling the dispatcher to switch to another process
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