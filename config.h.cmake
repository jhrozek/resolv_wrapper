/* Name of package */
#cmakedefine PACKAGE "${APPLICATION_NAME}"

/* Version number of package */
#cmakedefine VERSION "${APPLICATION_VERSION}"

#cmakedefine LOCALEDIR "${LOCALE_INSTALL_DIR}"
#cmakedefine DATADIR "${DATADIR}"
#cmakedefine LIBDIR "${LIBDIR}"
#cmakedefine PLUGINDIR "${PLUGINDIR}"
#cmakedefine SYSCONFDIR "${SYSCONFDIR}"
#cmakedefine BINARYDIR "${BINARYDIR}"
#cmakedefine SOURCEDIR "${SOURCEDIR}"

/************************** HEADER FILES *************************/

#cmakedefine HAVE_SYS_TYPES_H 1

/*************************** FUNCTIONS ***************************/

#cmakedefine HAVE_RES_INIT 1
#cmakedefine HAVE___RES_INIT 1
#cmakedefine HAVE_RES_9_INIT 1

#cmakedefine HAVE_RES_NINIT 1
#cmakedefine HAVE___RES_NINIT 1
#cmakedefine HAVE_RES_9_NINIT 1

#cmakedefine HAVE_RES_CLOSE 1
#cmakedefine HAVE___RES_CLOSE 1
#cmakedefine HAVE_RES_9_CLOSE 1

#cmakedefine HAVE_RES_NCLOSE 1
#cmakedefine HAVE___RES_NCLOSE 1
#cmakedefine HAVE_RES_9_NCLOSE 1

#cmakedefine HAVE_RES_QUERY 1
#cmakedefine HAVE___RES_QUERY 1
#cmakedefine HAVE_RES_9_QUERY 1

#cmakedefine HAVE_RES_SEARCH 1
#cmakedefine HAVE___RES_SEARCH 1
#cmakedefine HAVE_RES_9_SEARCH 1

#cmakedefine HAVE_RES_NQUERY 1
#cmakedefine HAVE___RES_NQUERY 1
#cmakedefine HAVE_RES_9_NQUERY 1

#cmakedefine HAVE_RES_NSEARCH 1
#cmakedefine HAVE___RES_NSEARCH 1
#cmakedefine HAVE_RES_9_NSEARCH 1

/*************************** LIBRARIES ***************************/

#cmakedefine HAVE_LIBRESOLV 1

/**************************** OPTIONS ****************************/

#cmakedefine HAVE_IPV6 1
#cmakedefine HAVE_RESOLV_IPV6_NSADDRS 1

#cmakedefine HAVE_ATTRIBUTE_PRINTF_FORMAT 1
#cmakedefine HAVE_DESTRUCTOR_ATTRIBUTE 1

/*************************** ENDIAN *****************************/

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#cmakedefine WORDS_BIGENDIAN 1
