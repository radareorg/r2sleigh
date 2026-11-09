/* K&R definitions: kr_short has a prototype in scope, so gcc states DW_AT_prototyped and its own `short c`; kr_bare has none. -std=gnu17. */
int kr_short (int a, int c);
__attribute__((noinline)) int
kr_short (a, c)
     int a;
     short c;
{
  return a + c;
}
__attribute__((noinline)) int
kr_bare (a, c)
     int a;
     short c;
{
  return a - c;
}
int main (int argc, char **argv) { (void)argv; return kr_short (argc, 70000) + kr_bare (argc, 3); }
