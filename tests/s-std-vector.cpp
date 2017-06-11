#include <vector>

std::vector<int> vec{1, 2, 3, 4, 5, 6, 7};

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

  std_vector_ret();
}
