#include <iostream>
#include "common-raii/common-raii.h"

int main (int argc, char ** argv)
{
  int v{44};
  std::cout << "calling with val " << v << " : " << commonRaii::test_func(v) << std::endl;
  return 0;
}
