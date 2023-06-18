#include <stdio.h>

static inline void * ERR_PTR(long error)
{
	return (void *) error;
}

#define	EINVAL		22	/* Invalid argument */

int main()
{
    printf("%016lx\n", ERR_PTR(-EINVAL));
    printf("%016lx\n", (-107));
    return 0;
}