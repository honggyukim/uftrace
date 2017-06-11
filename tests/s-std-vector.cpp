#include <vector>

std::vector<int> vec{1, 2, 3, 4, 5};

__attribute__((noinline))
void std_vector_arg(std::vector<int>& v)
{
  v = v;
}

__attribute__((noinline))
std::vector<int> std_vector_ret(void)
{
  return vec;
}

int main()
{
  std_vector_arg(vec);

  vec.push_back(6);
  std_vector_ret();

  vec.reserve(10);
  std_vector_arg(vec);

  vec.push_back(7);
  std_vector_arg(vec);
}
