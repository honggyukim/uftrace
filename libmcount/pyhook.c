/*
 * Python binding for mcount entry and exit
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
#include <libgen.h>

#include "pyhook.h"
#include "utils/utils.h"

static bool python_enabled = false;

static void *python_handle;
//static const char *libpython = "/usr/lib/python2.7/config-x86_64-linux-gnu/libpython2.7.so";
static const char *libpython = "libpython2.7.so";

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

static PyObject *pName, *pModule, *pFuncEntry, *pFuncExit;

#define INIT_PY_API_FUNC(func) \
	do { \
		__##func = dlsym(python_handle, #func); \
		if (!__##func) { \
			pr_err("dlsym for \"" #func "\" is failed!\n"); \
			python_enabled = false; \
			return -1; \
		} \
	} while (0)

/**
 * abs_dirname - parse given @pathname and set absolute dirname to @absdir
 * @absdir: input buffer that will store absolute dirname
 * @pathname: pathname string that can be either absolute or relative path
 *
 * This function parses the @pathname and sets absolute dirname to @absdir.
 *
 * Given @pathname sets @absdir as follows:
 *
 *    @pathname               | @absdir
 *   -------------------------+---------------
 *    mcount.py               | $PWD
 *    tests/mcount.py         | $PWD/tests
 *    ./tests/mcount.py       | $PWD/./tests
 *    /root/uftrace/mcount.py | /root/uftrace
 */
static int abs_dirname(char *absdir, const char *pathname)
{
	assert(pathname);

	char *path = strdup(pathname);
	char *dir = ".";

	if (strchr(path, '/'))
		dir = dirname(path);

	if (pathname[0] == '/') {
		sprintf(absdir, "%s", dir);
	}
	else {
		char cwd[BUFSIZ];
		if (!getcwd(cwd, sizeof(cwd))) {
			pr_err("getcwd error!\n");
			return -1;
		}
		sprintf(absdir, "%s/%s", cwd, dir);
	}
	free(path);

	return 0;
}

/* Import python module that is given by -p option */
static int import_python_module(const char *py_arg_pathname)
{
	char py_sys_dir[BUFSIZ];
	abs_dirname(py_sys_dir, py_arg_pathname);

	/* Set path to import a python module. */
	__PySys_SetPath(py_sys_dir);
	pr_dbg("PySys_SetPath(\"%s\") is done!\n", py_sys_dir);

	char *py_basename = basename((char*)py_arg_pathname);
	pName = __PyString_FromString(py_basename);
	pModule = __PyImport_Import(pName);
	if (pModule == NULL) {
		__PyErr_Print();
		pr_warn("%s.py cannot be imported!\n", py_arg_pathname);
		return -1;
	}

	return 0;
}

int python_init(const char *py_pathname)
{
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

	__Py_Initialize();

	/* import python module that is passed by -p option */
	if (import_python_module(py_pathname) < 0)
		return -1;

	pFuncEntry = __PyObject_GetAttrString(pModule, "mcount_entry");
	if (!pFuncEntry || !__PyCallable_Check(pFuncEntry)) {
		if (__PyErr_Occurred())
			__PyErr_Print();
		pr_warn("mcount_entry is not callable in mcount.py!\n");
	}
	pFuncExit = __PyObject_GetAttrString(pModule, "mcount_exit");
	if (!pFuncExit || !__PyCallable_Check(pFuncExit)) {
		if (__PyErr_Occurred())
			__PyErr_Print();
		pr_warn("mcount_exit is not callable in mcount.py!\n");
	}

	if (!pFuncEntry && !pFuncExit)
		return -1;

	python_enabled = true;
	pr_dbg("python_initialization for \"%s.py\" is done!\n", py_pathname);

	return 0;
}

int python_mcount_entry(unsigned long entry_addr, unsigned long ret_addr)
{
	PyObject *pythonArgument;
	PyObject *pValue;

	if (!pFuncEntry)
		return -1;

	pythonArgument = __PyTuple_New(2);
	PyObject *pValue1 = __PyInt_FromLong(entry_addr);
	PyObject *pValue2 = __PyInt_FromLong(ret_addr);
	assert(pValue1 && pValue2);

	__PyTuple_SetItem(pythonArgument, 0, pValue1);
	__PyTuple_SetItem(pythonArgument, 1, pValue2);

	pValue = __PyObject_CallObject(pFuncEntry, pythonArgument);

	if (pValue != NULL)
		pr_dbg("[python] mcount_entry: %#x\n", __PyLong_AsLong(pValue));
	else
		__PyErr_Print();

	return 0;
}

int python_mcount_exit(unsigned long ret_addr, long *retval)
{
	PyObject *pythonArgument;
	PyObject *pValue;

	if (!pFuncExit)
		return -1;

	if (retval) {
		/* Set the second argument if it has a return value. */
		pythonArgument = __PyTuple_New(2);

		PyObject *pValue2 = __PyInt_FromLong(*retval);
		__PyTuple_SetItem(pythonArgument, 1, pValue2);
	}
	else {
		pythonArgument = __PyTuple_New(1);
	}
	PyObject *pValue1 = __PyInt_FromLong(ret_addr);
	__PyTuple_SetItem(pythonArgument, 0, pValue1);

	pValue = __PyObject_CallObject(pFuncExit, pythonArgument);

	if (pValue != NULL)
		pr_dbg("[python] mcount_exit: %#x\n", __PyLong_AsLong(pValue));
	else
		__PyErr_Print();

	return 0;
}
