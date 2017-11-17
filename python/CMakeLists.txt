FIND_PACKAGE(PythonInterp 3.4 REQUIRED)

EXECUTE_PROCESS(COMMAND ${PYTHON_EXECUTABLE} -c "from sys import stdout; from distutils import sysconfig; stdout.write(sysconfig.get_python_lib())" OUTPUT_VARIABLE PYTHON_INSTALL_DIR)
MESSAGE(STATUS "Python install dir is ${PYTHON_INSTALL_DIR}")
MESSAGE(STATUS "Python version is ${PYTHON_VERSION_STRING}")

FILE(GLOB yaca_SRCS yaca/*.py)
INSTALL (FILES ${yaca_SRCS} DESTINATION ${PYTHON_INSTALL_DIR}/${PROJECT_NAME})
