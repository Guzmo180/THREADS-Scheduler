#pragma once


#define STATUS_EMPTY 0 
#define STATUS_READY 1 
#define STATUS_RUNNING 2
#define STATUS_BLOCKED 3
#define STATUS_QUIT 4 
typedef struct _process
{
	struct _process*        nextReadyProcess;
	struct _process*		nextSiblingProcess;

	struct _process*		pParent;   
	struct _process*        pChildren;
	struct _process*        pActiveChildren;
	struct _process*        pChildrenThatExited;
	struct _process*        pJoiners;
	

	char           name[MAXNAME];     /* Process name */
	char           startArgs[MAXARG]; /* Process arguments */
	void*		   context;           /* Process's current context */
	short          pid;               /* Process id (pid) */
	int            priority;
	int (*entryPoint) (void*);        /* The entry point that is called from launch */
	char*	       stack;
	unsigned int   stacksize;
	int            status;            /* READY, QUIT, BLOCKED, etc. */
	int			   exitCode;   
} Process;