#include "../header/py_call.h"
void py_call()
{
    Py_Initialize();
    PyRun_SimpleString("import webbrowser,os\n"
                       "os.system(\"ps -ef | grep firefox | awk '{print $2}' | xargs kill -9\")\n"
                       "webbrowser.open('localhost',new=0)\n");
    Py_FinalizeEx();
}
  