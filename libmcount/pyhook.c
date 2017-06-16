/*
 * Python binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <dlfcn.h>

#include "pyhook.h"
#include "utils/utils.h"
#include "utils/symbol.h"

static bool python_enabled = false;

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
	PY_ARG_ENTRY_ADDR = 0,
	PY_ARG_RET_ADDR,
	PY_ARG_SYMNAME,
	PY_ARG_RETVAL,
};

/* The order has to be aligned with enum py_args */
static const char *py_args_table[] = {
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
			python_enabled = false; \
			return -1; \
		} \
	} while (0)

static void remove_py_suffix(char *py_name)
{
	int len = strlen(py_name);
	assert(len > 3 &&
		py_name[len - 3] == '.' &&
		py_name[len - 2] == 'p' &&
		py_name[len - 1] == 'y');
	py_name[len - 3] = '\0';
}

/* Import python module that is given by -p option */
static int import_python_module(char *py_arg_pathname)
{
	char py_sysdir[PATH_MAX];
	absolute_dirname(py_arg_pathname, py_sysdir);

	/* Set path to import a python module. */
	__PySys_SetPath(py_sysdir);
	pr_dbg("PySys_SetPath(\"%s\") is done!\n", py_sysdir);

	char *py_basename = basename(py_arg_pathname);
	remove_py_suffix(py_basename);

	pName = __PyString_FromString(py_basename);
	pModule = __PyImport_Import(pName);
	if (pModule == NULL) {
		__PyErr_Print();
		pr_warn("%s.py cannot be imported!\n", py_arg_pathname);
		return -1;
	}

	return 0;
}

int python_uftrace_entry(unsigned long entry_addr, unsigned long ret_addr)
{
	PyObject *pythonArgument;
	PyObject *pValue;

	if (!pFuncEntry)
		return -1;

	struct sym *sym = find_symtabs(&symtabs, entry_addr);

	/* Entire arguments are passed into a single dictionary. */
	PyObject *pDict = __PyDict_New();

	PyObject *pValue1 = __PyInt_FromLong(entry_addr);
	PyObject *pValue2 = __PyInt_FromLong(ret_addr);
	PyObject *pSym  = __PyString_FromString(sym->name);
	assert(pDict && pValue1 && pValue2 && pSym);

	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_ENTRY_ADDR], pValue1);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_RET_ADDR], pValue2);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_SYMNAME], pSym);

	/* Argument list must be passed in a tuple. */
	pythonArgument = __PyTuple_New(1);
	__PyTuple_SetItem(pythonArgument, 0, pDict);

	pValue = __PyObject_CallObject(pFuncEntry, pythonArgument);

	if (pValue != NULL)
		pr_dbg("[python] uftrace_entry: %#x\n", __PyLong_AsLong(pValue));
	else
		__PyErr_Print();

	return 0;
}

int python_uftrace_exit(unsigned long ret_addr, long *retval)
{
	PyObject *pythonArgument;
	PyObject *pValue;

	if (!pFuncExit)
		return -1;

	/* Entire arguments are passed into a single dictionary. */
	PyObject *pDict = __PyDict_New();

	PyObject *pValue1 = __PyInt_FromLong(ret_addr);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_RET_ADDR], pValue1);

	if (retval) {
		PyObject *pValue2 = __PyInt_FromLong(*retval);
		__PyDict_SetItemString(pDict, py_args_table[PY_ARG_RETVAL], pValue2);
	}

	/* Argument list must be passed in a tuple. */
	pythonArgument = __PyTuple_New(1);
	__PyTuple_SetItem(pythonArgument, 0, pDict);

	pValue = __PyObject_CallObject(pFuncExit, pythonArgument);

	if (pValue != NULL)
		pr_dbg("[python] uftrace_exit: %#x\n", __PyLong_AsLong(pValue));
	else
		__PyErr_Print();

	return 0;
}

int python_init(char *py_pathname)
{
	pr_dbg("initialize python\n");

	/* bind script_mcount functions to python */
	script_uftrace_entry = python_uftrace_entry;
	script_uftrace_exit = python_uftrace_exit;

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
	INIT_PY_API_FUNC(PyString_AsString);
	INIT_PY_API_FUNC(PyLong_AsLong);

	INIT_PY_API_FUNC(PyDict_New);
	INIT_PY_API_FUNC(PyLong_FromLong);
	INIT_PY_API_FUNC(PyDict_SetItem);
	INIT_PY_API_FUNC(PyDict_SetItemString);
	INIT_PY_API_FUNC(PyDict_GetItem);

	__Py_Initialize();

	/* import python module that is passed by -p option */
	if (import_python_module(py_pathname) < 0)
		return -1;

	pFuncEntry = __PyObject_GetAttrString(pModule, "uftrace_entry");
	if (!pFuncEntry || !__PyCallable_Check(pFuncEntry)) {
		if (__PyErr_Occurred())
			__PyErr_Print();
		pr_warn("uftrace_entry is not callable in mcount.py!\n");
	}
	pFuncExit = __PyObject_GetAttrString(pModule, "uftrace_exit");
	if (!pFuncExit || !__PyCallable_Check(pFuncExit)) {
		if (__PyErr_Occurred())
			__PyErr_Print();
		pr_warn("uftrace_exit is not callable in mcount.py!\n");
	}

	if (!pFuncEntry && !pFuncExit)
		return -1;

	python_enabled = true;
	pr_dbg("python_initialization for \"%s.py\" is done!\n", py_pathname);

	return 0;
}
