#include <stdio.h>

#include "version.h"

int netz_major_version()
{
    return NETZ_MAJOR_VERSION;
}

int netz_minor_version()
{
    return NETZ_MINOR_VERSION;
}

char *netz_version(char *version_string)
{
    sprintf(version_string, "%s", NETZ_VERSION);

    return version_string;
}

char *netz_build_date(char *build_date_string)
{
    sprintf(build_date_string, "%s", NETZ_BUILD_DATE);

    return build_date_string;
}
