/*
 * Python script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#if !HAVE_LIBPYTHON2

/* Do nothing if libpython2.7.so is not installed. */

#else /* !HAVE_LIBPYTHON2 */

#include <dlfcn.h>
#include "utils/symbol.h"
#include "utils/fstack.h"
#include "utils/script.h"
#include "utils/script-python.h"

/* python library name, it only supports python 2.7 as of now */
static const char *libpython = "libpython2.7.so";

/* python library handle returned by dlopen() */
static void *python_handle;

static PyAPI_FUNC(void) (*__Py_Initialize)(void);
static PyAPI_FUNC(void) (*__PySys_SetPath)(char *);
static PyAPI_FUNC(void) (*__PyErr_Print)(void);
static PyAPI_FUNC(int) (*__PyCallable_Check)(PyObject *);
static PyAPI_FUNC(PyObject *) (*__PyImport_Import)(PyObject *name);
static PyAPI_FUNC(PyObject *) (*__PyTuple_New)(Py_ssize_t size);
static PyAPI_FUNC(PyObject *) (*__PyErr_Occurred)(void);
static PyAPI_FUNC(int) (*__PyTuple_SetItem)(PyObject *, Py_ssize_t, PyObject *);
static PyAPI_FUNC(PyObject *) (*__PyObject_GetAttrString)(PyObject *, const char *);
static PyAPI_FUNC(PyObject *) (*__PyObject_CallObject)(PyObject *callable_object, PyObject *args);

static PyAPI_FUNC(PyObject *) (*__PyString_FromString)(const char *);
static PyAPI_FUNC(PyObject *) (*__PyInt_FromLong)(long);
static PyAPI_FUNC(PyObject *) (*__PyLong_FromUnsignedLongLong)(unsigned PY_LONG_LONG);

static PyAPI_FUNC(char *) (*__PyString_AsString)(PyObject *);
static PyAPI_FUNC(long) (*__PyLong_AsLong)(PyObject *);

static PyAPI_FUNC(PyObject *) (*__PyDict_New)(void);
static PyAPI_FUNC(int) (*__PyDict_SetItem)(PyObject *mp, PyObject *key, PyObject *item);
static PyAPI_FUNC(int) (*__PyDict_SetItemString)(PyObject *dp, const char *key, PyObject *item);
static PyAPI_FUNC(PyObject *) (*__PyDict_GetItem)(PyObject *mp, PyObject *key);

static PyAPI_FUNC(PyObject *) (*__PyLong_FromLong)(long);

static PyObject *pName, *pModule, *pFuncEntry, *pFuncExit;

extern struct symtabs symtabs;

enum py_args {
	PY_ARG_TID = 0,
	PY_ARG_DEPTH,
	PY_ARG_START_TIME,
	PY_ARG_END_TIME,
	PY_ARG_TOTAL_TIME,
	PY_ARG_ENTRY_ADDR,
	PY_ARG_RET_ADDR,
	PY_ARG_SYMNAME,
	PY_ARG_RETVAL,
};

/* The order has to be aligned with enum py_args above. */
static const char *py_args_table[] = {
	"tid",
	"depth",
	"start_time",
	"end_time",
	"total_time",
	"entry_addr",
	"ret_addr",
	"symname",
	"retval",
};

#define INIT_PY_API_FUNC(func) \
	do { \
		__##func = dlsym(python_handle, #func); \
		if (!__##func) { \
			pr_err("dlsym for \"" #func "\" is failed!\n"); \
			return -1; \
		} \
	} while (0)

static char *remove_py_suffix(char *py_name)
{
	char *ext = strrchr(py_name, '.');

	if (!ext)
		return NULL;

	*ext = '\0';
	return py_name;
}

/* Import python module that is given by -p option. */
static int import_python_module(char *py_pathname)
{
	char py_sysdir[PATH_MAX];
	if (absolute_dirname(py_pathname, py_sysdir) == NULL)
		return -1;

	/* Set path to import a python module. */
	__PySys_SetPath(py_sysdir);
	pr_dbg("PySys_SetPath(\"%s\") is done!\n", py_sysdir);

	char *py_basename = basename(py_pathname);
	remove_py_suffix(py_basename);

	pName = __PyString_FromString(py_basename);
	pModule = __PyImport_Import(pName);
	if (pModule == NULL) {
		__PyErr_Print();
		pr_warn("%s.py cannot be imported!\n", py_pathname);
		return -1;
	}

	return 0;
}

#ifdef LIBMCOUNT

int python_uftrace_entry(struct mcount_ret_stack *rstack, char *symname)
{
	if (unlikely(!pFuncEntry))
		return -1;

	int tid = rstack->tid;
	int depth = rstack->depth;
	uint64_t start_time = rstack->start_time;
	unsigned long entry_addr = rstack->child_ip;
	unsigned long ret_addr = *(rstack->parent_loc);

	/* Entire arguments are passed into a single dictionary. */
	PyObject *pDict = __PyDict_New();

	/* Make a PyObject from symbol. */
	PyObject *pSym;
	if (symname) {
		pSym  = __PyString_FromString(symname);
	} else {
		struct sym *sym = find_symtabs(&symtabs, entry_addr);
		symname = symbol_getname(sym, entry_addr);
		pSym  = __PyString_FromString(symname);
		symbol_putname(sym, symname);
	}

	PyObject *pTid = __PyInt_FromLong(tid);
	PyObject *pDepth = __PyInt_FromLong(depth);
	PyObject *pStartTime = __PyLong_FromUnsignedLongLong(start_time);
	PyObject *pEntryAddr = __PyInt_FromLong(entry_addr);
	PyObject *pRetAddr = __PyInt_FromLong(ret_addr);

	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_TID], pTid);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_DEPTH], pDepth);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_START_TIME], pStartTime);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_ENTRY_ADDR], pEntryAddr);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_RET_ADDR], pRetAddr);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_SYMNAME], pSym);

	/* Argument list must be passed in a tuple. */
	PyObject *pythonArgument = __PyTuple_New(1);
	__PyTuple_SetItem(pythonArgument, 0, pDict);

	/* Call python function "uftrace_entry". */
	PyObject *pReturn = __PyObject_CallObject(pFuncEntry, pythonArgument);

	if (likely(pReturn != NULL)) {
		pr_dbg3("[python] uftrace_entry returns %#x\n",
			__PyLong_AsLong(pReturn));
	}
	else
		__PyErr_Print();

	return 0;
}

int python_uftrace_exit(struct mcount_ret_stack *rstack,
			char *symname,
			long *retval)
{
	if (unlikely(!pFuncExit))
		return -1;

	int tid = rstack->tid;
	int depth = rstack->depth;
	uint64_t start_time = rstack->start_time;
	uint64_t end_time = rstack->end_time;
	unsigned long entry_addr = rstack->child_ip;
	unsigned long ret_addr = rstack->parent_ip;

	/* Entire arguments are passed into a single dictionary. */
	PyObject *pDict = __PyDict_New();

	/* Make a PyObject from symbol. */
	PyObject *pSym;
	if (symname) {
		pSym  = __PyString_FromString(symname);
	} else {
		struct sym *sym = find_symtabs(&symtabs, entry_addr);
		symname = symbol_getname(sym, entry_addr);
		pSym  = __PyString_FromString(symname);
		symbol_putname(sym, symname);
	}

	PyObject *pTid = __PyInt_FromLong(tid);
	PyObject *pDepth = __PyInt_FromLong(depth);
	PyObject *pStartTime = __PyLong_FromUnsignedLongLong(start_time);
	PyObject *pEndTime = __PyLong_FromUnsignedLongLong(end_time);
	PyObject *pRetAddr = __PyInt_FromLong(ret_addr);

	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_TID], pTid);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_DEPTH], pDepth);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_START_TIME], pStartTime);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_END_TIME], pEndTime);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_RET_ADDR], pRetAddr);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_SYMNAME], pSym);

	if (retval) {
		PyObject *pRetVal = __PyInt_FromLong(*retval);
		__PyDict_SetItemString(pDict, py_args_table[PY_ARG_RETVAL], pRetVal);
	}

	/* Argument list must be passed in a tuple. */
	PyObject *pythonArgument = __PyTuple_New(1);
	__PyTuple_SetItem(pythonArgument, 0, pDict);

	/* Call python function "uftrace_exit". */
	PyObject *pReturn = __PyObject_CallObject(pFuncExit, pythonArgument);

	if (likely(pReturn != NULL)) {
		pr_dbg3("[python] uftrace_exit returns %#x\n",
			__PyLong_AsLong(pReturn));
	}
	else
		__PyErr_Print();

	return 0;
}

#else /* LIBMCOUNT */

int python_uftrace_data_entry(struct ftrace_task_handle *task,
			      struct uftrace_record *rstack,
			      char *symname)
{
	if (unlikely(!pFuncEntry))
		return -1;

	int tid = task->tid;
	int depth = rstack->depth;
	uint64_t start_time = rstack->time;
	unsigned long entry_addr = rstack->addr;

	/* Entire arguments are passed into a single dictionary. */
	PyObject *pDict = __PyDict_New();

	/* Make a PyObject from symbol. */
	PyObject *pSym;
	if (symname) {
		pSym  = __PyString_FromString(symname);
	} else {
		struct symtabs *symtabs = &task->h->sessions.first->symtabs;
		struct sym *sym = find_symtabs(symtabs, entry_addr);
		symname = symbol_getname(sym, entry_addr);
		pSym  = __PyString_FromString(symname);
		symbol_putname(sym, symname);
	}

	PyObject *pTid = __PyInt_FromLong(tid);
	PyObject *pDepth = __PyInt_FromLong(depth);
	PyObject *pStartTime = __PyLong_FromUnsignedLongLong(start_time);
	PyObject *pEntryAddr = __PyInt_FromLong(entry_addr);
//	PyObject *pRetAddr = __PyInt_FromLong(ret_addr);

	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_TID], pTid);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_DEPTH], pDepth);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_START_TIME], pStartTime);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_ENTRY_ADDR], pEntryAddr);
//	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_RET_ADDR], pRetAddr);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_SYMNAME], pSym);

	/* Argument list must be passed in a tuple. */
	PyObject *pythonArgument = __PyTuple_New(1);
	__PyTuple_SetItem(pythonArgument, 0, pDict);

	/* Call python function "uftrace_entry". */
	PyObject *pReturn = __PyObject_CallObject(pFuncEntry, pythonArgument);

	if (likely(pReturn != NULL)) {
		pr_dbg3("[python] uftrace_entry returns %#x\n",
			__PyLong_AsLong(pReturn));
	}
	else
		__PyErr_Print();

	return 0;
}

int python_uftrace_data_exit(struct ftrace_task_handle *task,
			     struct uftrace_record *rstack,
			     char *symname,
			     uint64_t total_time)
{
	if (unlikely(!pFuncExit))
		return -1;

	int tid = task->tid;
	int depth = rstack->depth;
	unsigned long entry_addr = rstack->addr;

	/* Entire arguments are passed into a single dictionary. */
	PyObject *pDict = __PyDict_New();

	/* Make a PyObject from symbol. */
	PyObject *pSym;
	if (symname) {
		pSym  = __PyString_FromString(symname);
	} else {
		struct symtabs *symtabs = &task->h->sessions.first->symtabs;
		struct sym *sym = find_symtabs(symtabs, entry_addr);
		symname = symbol_getname(sym, entry_addr);
		pSym  = __PyString_FromString(symname);
		symbol_putname(sym, symname);
	}

	PyObject *pTid = __PyInt_FromLong(tid);
	PyObject *pDepth = __PyInt_FromLong(depth);

	/* Create PyObject only total_time instead of start_time and end_time. */
	PyObject *pTotalTime = __PyLong_FromUnsignedLongLong(total_time);

//	PyObject *pRetAddr = __PyInt_FromLong(ret_addr);

	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_TID], pTid);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_DEPTH], pDepth);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_TOTAL_TIME], pTotalTime);
//	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_RET_ADDR], pRetAddr);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_SYMNAME], pSym);

#if 0
	if (retval) {
		PyObject *pRetVal = __PyInt_FromLong(*retval);
		__PyDict_SetItemString(pDict, py_args_table[PY_ARG_RETVAL], pRetVal);
	}
#endif

	/* Argument list must be passed in a tuple. */
	PyObject *pythonArgument = __PyTuple_New(1);
	__PyTuple_SetItem(pythonArgument, 0, pDict);

	/* Call python function "uftrace_exit". */
	PyObject *pReturn = __PyObject_CallObject(pFuncExit, pythonArgument);

	if (likely(pReturn != NULL)) {
		pr_dbg3("[python] uftrace_exit returns %#x\n",
			__PyLong_AsLong(pReturn));
	}
	else
		__PyErr_Print();

	return 0;
}

#endif /* LIBMCOUNT */

int script_init_for_python(char *py_pathname)
{
	pr_dbg("initialize python\n");

	/* Bind script_uftrace functions to python's. */
#ifdef LIBMCOUNT
	script_uftrace_entry = python_uftrace_entry;
	script_uftrace_exit = python_uftrace_exit;
#else
	script_uftrace_data_entry = python_uftrace_data_entry;
	script_uftrace_data_exit = python_uftrace_data_exit;
#endif

	python_handle = dlopen(libpython, RTLD_LAZY);
	if (!python_handle) {
		pr_warn("%s cannot be loaded!\n", libpython);
		return -1;
	}

	INIT_PY_API_FUNC(Py_Initialize);
	INIT_PY_API_FUNC(PySys_SetPath);
	INIT_PY_API_FUNC(PyErr_Print);
	INIT_PY_API_FUNC(PyCallable_Check);
	INIT_PY_API_FUNC(PyImport_Import);
	INIT_PY_API_FUNC(PyTuple_New);
	INIT_PY_API_FUNC(PyErr_Occurred);

	INIT_PY_API_FUNC(PyTuple_SetItem);
	INIT_PY_API_FUNC(PyObject_GetAttrString);
	INIT_PY_API_FUNC(PyObject_CallObject);

	INIT_PY_API_FUNC(PyString_FromString);
	INIT_PY_API_FUNC(PyInt_FromLong);
	INIT_PY_API_FUNC(PyLong_FromUnsignedLongLong);
	INIT_PY_API_FUNC(PyString_AsString);
	INIT_PY_API_FUNC(PyLong_AsLong);

	INIT_PY_API_FUNC(PyDict_New);
	INIT_PY_API_FUNC(PyLong_FromLong);
	INIT_PY_API_FUNC(PyDict_SetItem);
	INIT_PY_API_FUNC(PyDict_SetItemString);
	INIT_PY_API_FUNC(PyDict_GetItem);

	__Py_Initialize();

	/* Import python module that is passed by -p option. */
	if (import_python_module(py_pathname) < 0)
		return -1;

	pFuncEntry = __PyObject_GetAttrString(pModule, "uftrace_entry");
	if (!pFuncEntry || !__PyCallable_Check(pFuncEntry)) {
		if (__PyErr_Occurred())
			__PyErr_Print();
		pr_warn("uftrace_entry is not callable!\n");
		pFuncEntry = NULL;
	}
	pFuncExit = __PyObject_GetAttrString(pModule, "uftrace_exit");
	if (!pFuncExit || !__PyCallable_Check(pFuncExit)) {
		if (__PyErr_Occurred())
			__PyErr_Print();
		pr_warn("uftrace_exit is not callable!\n");
		pFuncExit = NULL;
	}

	if (!pFuncEntry && !pFuncExit) {
		pr_warn("python_initialization for \"%s.py\" is failed!\n",
			py_pathname);
		return -1;
	}

	pr_dbg("python_initialization for \"%s.py\" is done!\n", py_pathname);

	return 0;
}

#endif /* !HAVE_LIBPYTHON2 */