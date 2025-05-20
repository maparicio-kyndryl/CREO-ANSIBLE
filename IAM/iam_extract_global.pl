#!/usr/bin/perl
#=========================================================================
# (C) Copyright 2021 Kyndryl
#=========================================================================
# Script Name    : iam_extract.pl
# Script Purpose : extract iam data
# Parameters     : $1 IAM customer name (optional)
#                  $2 password file (optional)
#                  $3 group file (optional)
#                  $4 Output file name (optional)
#                  $5 Hostname (optional)
# Output         : file in IAM .mef format
# Dependencies   : Perl
#-------------------------------------------------------------------------------
# Version Date	        # Author              Description
#-------------------------------------------------------------------------------
# V3.0.0  2006-04-28   # Matthew Waterfield  Ported from ksh and to .mef v2
# V3.1.0  2006-06-22   # Matthew Waterfield  Fix open issue on old perls
# V4.0.0  2006-10-18   # Matthew Waterfield  Enhance to get state
# V4.1.0  2006-10-25   # Matthew Waterfield  Add output file checks
# V4.2.0  2006-11-06   # Matthew Waterfield  Change to GetOptions and tidy
# V4.2.1  2006-11-06   # Matthew Waterfield  Check priv groups against URT list
# V5.0.0  2007-05-23   # iwong  Added parsing of gecos for IBM SSSSSS CCC, added 3-digit CC to 2-digit
#         Added parsing of sudoers, and sudoer group processing
#         Added --sudoers flag
#         update ouput to include:
#         usergecos = CC/I/SSSSSS//gecos - process gecos and pulls Serial and Country Code
#         usergroup =  list of groups which give this ID SUDO priviledges
#         userprivgroup = SUDO if found in sudoerReport, else blank
# V5.1.0  2007-07-18   # iwong  Updated code to default status=C, serial="", and  cc=US, if not IBM
#             Setup default customer, and added new customer flag
#                   Updated code adding hostname to default mef file name
# V5.1.1  2007-08-02   # iwong  Updated code to read URT format CCC/I/SSSSSS//gecos
# V5.1.2  2007-08-28   # iwong  Updated code to fix problem with -meffile flag
# V5.1.3  2007-09-13   # iwong  Updated code to warn if no sudoers files found
# V5.2.0  2007-09-26   # iwong  Updated code to generated scm formated output file
# V5.2.2  2007-11-07   # iwong  Updated code read in cust and comment fomr URT format CCC/I/SSSSSS/cust/comment
#                      #        Updated default user status state to enabled(0), if state unknown
# V5.2.3  2007-11-28   # iwong  Updated warning messages to indicated which files are missing
#          #        Updated code to indicate if SUDO priv is granted by a group(SUDO-GRP) or user(SUDO-USR)
#          #        Moved OS default file stanza to after arg assignments
# V5.2.4  2007-11-29   # iwong  Updated code output .scm9 format, which includes auditDATE
#                      #        Fixed problem accounts disabled with account_locked in SECUSER
# V5.2.5  2007-12-05   # iwong  Updated code to check for HP-UX systems(TCB and non-TCB)
# V5.2.6  2007-12-11   # leduc  If comments contain IBM flag = I
# V5.2.7  2008-01-25   # iwong  Updated code changing SUDO-USR to SUDO and SUDO-GRP to list of sudo groups

# V5.2.8  2008-02-21   # iwong  Updated code output .mef format
# V5.2.9  2008-02-21   # iwong  getprpw command to properly report HP disabled users
# V5.2.10 2008-02-21   # iwong  Bypass disabled check for * in passwd field in passwd file on hpux TCB systems
#             Updated output file name, if customer different from default IBM
#             added debug flag
# V5.2.11 2008-02-21   # iwong  Created new parsespw_hpux subroutine to check getprpw or shadow file
# V6.0    2008-04-11   # iwong  Added -scm flag, to output scm9 format, changed meffile flag to outfile
#             Output OS type in scm formated files
#             Recognize OSR privileged user and groups per OS type
#             Updated groups and privileges fields include OSR ans SUDO privs
#             Add script integrity cksum check
#             Uniquify group and SUDO group lists
#             Remove 3-digit CC conversion
#             Added -privfile flag to read in additional priv groups from a file
#             Updated code output .mef3 format
# V6.1    2008-04-18   # iwong  Updated code group field output to list all groups a user is a member
#             Commented out cksum check
# V6.2    2008-04-18   # iwong  Removed description matching for URT/CIO/IBM formats
# V6.3    2008-04-23   # iwong  Fixed problem with primary groups, not shown for ids not in any groups
#             Add wheel to Linux default priv group list
#             Fixed problem with reading in additional priv group
# V6.4    2008-05-01   # iwong  Added code to skip Defaults in sudoers file
#               Added code to fix problem with lines with spaces/tabs after \ in sudoers file
#               Added additional debug statement for sudoers processing
#               Added additional processing of ALL keyword in sudoers
# V6.5    2008-05-13   # iwong  Commented out cksum code
# V6.6    2008-05-15   # iwong  Added -mef flag, to output mef2 format
# V6.7    2008-06-03   # iwong  Added code to process groups in the User_Alias
# V6.8    2008-06-11   # iwong  Added code ignore netgroup ids +@user, any id starting with +
# V6.9    2008-06-20   # iwong  Added code adding dummy record to end of output file with date and versioning information
# V6.10   2008-07-28   # iwong  Updated dummy record to include 000 cc
# V7.0    2008-10-09   # iwong  Added code to process/recognize Host_Aliases in sudoers file
#                               Added code to process/recognize User_Aliases only if they are used
#                               Added code to list Linux groups with gid < 99 as privileged
#                               Updated code for processing primary groups
# V7.1    2008-01-09   # iwong  Added code to get sudo version
#                               Updated signature record to include FN= amd SUDO =
#                               Update Version removing date
# V7.2    2008-01-09   # iwong  Fixed problem with exiting sudoers processing on invalid group
# V7.3    2009-04-02   # M Ram  Added code to Ignore SUDOALL if "ALL=!SUDUSUDO" rule found
#               Updated code to recognize FQDN in sudoers hostlist
#               Added code to make same output Perl & KSH
# V7.4    2009-04-15   # M Ram  Added code to print custom signature for dummy id
#               Added code to check SSH public key authentation status for users having password "*" in passwd file
# V7.5    2009-08-24   # M Ram  Added code to fetch IDs from NIS
#     2009-08-24   # M Ram  Added code to process Netuser and Netgroup IDs ( start with + )
#     2009-08-25   # M Ram  Added code to print user last logon date for AIX
#     2009-09-23   # M Ram  Fixed the problem with disabled id has password like *LK*{crypt} in solaris
#     2009-09-24   # M Ram  Updated code to process PRIV file in linux environment
#        2010-01-13 # Anatoly Bondyuk    Added code to get of the support of reception of the list of users (including services LDAP, NIS, NIS +) by help of system functions getent and lsuser (lsgroup)
#        2010-02-01 # Anatoly Bondyuk    Fixed the issue with the checking of the passwd file
#        2010-02-24 # Anatoly Bondyuk    Fixed the issue with the operator of matching of strings (eq, ne instead !=, ==) for checking on the SSH-status
#        2010-02-25 # Anatoly Bondyuk    Fixed the issue with storing of data in a hash on processing of group members
#        2010-03-03 # Anatoly Bondyuk    Added correction of transferred value of paths in functions of processing of users and groups
#        2010-03-05 # Anatoly Bondyuk    Added the cleaning of hashes after working of NIS-piece of the code
#        2010-03-09 # Anatoly Bondyuk    Added the fix for the checking SUDO-aliases by the hostname with the help of a long hostname
#        2010-03-09 # Anatoly Bondyuk    Added the fix for checking SUDO-privileges for NIS's accounts
#        2010-03-11 # Anatoly Bondyuk    Added the possibility to analyze the alternative SSHD file and the SUDO file on SunOS
# V7.6   2010-04-01 # Vladislav Tembekov Added code to fetch Ids from LDAP
#        2010-05-03 # Vladislav Tembekov Added new option (--fqdn) to support FQDN format in MEF file
# V7.6.2 2010-05-21 # Vladislav Tembekov Fixed code to Ignore SUDOALL if "ALL=!somewhat" rule found
#        2010-05-26 # Vladislav Tembekov Added more default paths for search sudoers file
# V7.6.3 2010-06-15 # Vladislav Tembekov Fixed the issue with --hostname option.
#        2010-06-16 # Vladislav Tembekov Fixed the issue with --passwd and --group options. Added --noautoldap option
# V7.6.4 2010-07-05 # Vladislav Tembekov Added NIS+ support
# V7.6.5 2010-08-04 # Vladislav Tembekov Fixed host name bug. Changed logging. Fixed some minor bugs.
# V7.6.6 2010-09-07 # Vladislav Tembekov Changed checksum algorithm. Updated processing LDAP userids.
# V7.6.7 2010-09-15 # Vladislav Tembekov Fixed possible issue with user state
# V7.6.8 2010-10-15 # Vladislav Tembekov Changed default output file directory.
# V7.6.9 2010-12-02 # Vladislav Tembekov Additional check of privileged groups was added
# V7.7   2010-12-14 # Vladislav Tembekov Added code to process include and includedir directives in sudoers file
# V7.7.1 2011-01-04 # Vladislav Tembekov Change level of some messages from error to warning
# V7.7.2 2011-01-19 # Vladislav Tembekov Change processing command line arguments, fixed issue on HPUNIX with hostname length limitation
# V7.7.3 2011-01-25 # Vladislav Tembekov Added --customerOnly and --ibmOnly options, fixed issue with fetching groups from LDAP in autoldap mode
# V7.7.4 2011-01-28 # Vladislav Tembekov Added code to print user last logon date for Linux, Solaris
# V7.7.5 2011-02-02 # Vladislav Tembekov Added code to filter LDAP users on AIX
# V7.7.6 2011-02-15 # Vladislav Tembekov Changed trim function
# V7.7.7 2011-02-21 # Vladislav Tembekov Fixed hostname issue
# V7.7.8 2011-02-24 # Vladislav Tembekov Fixed cycling call in ProcessUserAlias and add_name functions
# V7.7.9 2011-03-03 # Vladislav Tembekov Added --owner flag to change output file permission, remove "|" in gecos filed
# V7.8   2011-03-10 # Vladislav Tembekov Added code to filter LDAP users by host attribute in case of PAM authentication,fixed HP Unix OS name
# V7.8.1 2011-03-16 # Vladislav Tembekov Fixed issue with last logon date on SanOS
# V7.8.2 2011-03-29 # Vladislav Tembekov Added --dlld flag to disable print last logon date 
# V7.8.3 2011-04-04 # Vladislav Tembekov Added check for LDAP IDs in passwd file
# V7.8.4 2011-04-06 # Vladislav Tembekov Added code to print IDs SUDO-aliases
# V7.8.5 2011-04-20 # Vladislav Tembekov Improved AIX LDAP filter
# V7.8.6 2011-05-19 # Vladislav Tembekov Changed code to get FQDN
# V7.8.7 2011-06-03 # Vladislav Tembekov Improved LDAP groups processing
# V7.8.8 2011-06-07 # Vladislav Tembekov Changed code to get sudo version
# V7.8.9 2011-06-14 # Vladislav Tembekov Added code to Ignore SUDOALL if "ALL=NOEXEC" rule found
# V7.9   2011-06-17 # Vladislav Tembekov Added code to set CMD_ENV=xpg4 if TRU64 is found
# V7.9.1 2011-08-03 # Vladislav Tembekov Added code to parsing local groups while processing LDAP/NIS IDs
# V7.9.2 2011-08-16 # Vladislav Tembekov Additional check of privileged ID was added
# V7.9.3 2011-08-30 # Vladislav Tembekov Improved LDAP ID processing
# V7.9.4 2011-09-05 # Vladislav Tembekov Improved debug logging functionality
# V7.9.5 2011-09-14 # Vladislav Tembekov Changed regexp for correct macthing IBM SSSSSS CCC GECOS record format 
# V7.9.6 2011-09-21 # Vladislav Tembekov Fixed issue in getfqdn function
# V7.9.7 2011-09-23 # Vladislav Tembekov Added --dev switch, only for developer 
# V7.9.8 2011-10-18 # Vladislav Tembekov Fixed issue when hostname command returns fqdn
# V7.9.9 2011-10-19 # Vladislav Tembekov Improved code to check SSH public key authentation status for locked users 
# V8     2011-11-16 # Vladislav Tembekov Fixed directory name issue while parsing #includedir sudoers directive
# V8.1   2011-11-22 # Vladislav Tembekov Added additional LDAP users checking on AIX
# V8.1.1 2011-11-30 # Vladislav Tembekov Added GSA functionality, --nogsa switch
# V8.1.2 2012-01-05 # Vladislav Tembekov Added check authorized_keys2 file
# V8.1.3 2012-01-16 # Vladislav Tembekov Added using idsldapsearch cmd on AIX if ldapserach cmd is not available
# V8.1.4 2012-01-16 # Vladislav Tembekov Disable ID on HPUX when shadow file doesn't exist and password field contains "*"
# V8.1.5 2012-01-25 # Vladislav Tembekov Disable printing SUDO_userid and SUDO_ALIAS(ALIANAME) in the same time
# V8.1.6 2012-02-02 # Vladislav Tembekov Added check hostalias if ALL rule found 
# V8.1.7 2012-02-09 # Vladislav Tembekov Rename script from urt_ to iam_
# V8.1.8 2012-04-13 # Vladislav Tembekov Fixed extraction GSA users from sudoers file issue
# V8.1.9 2012-04-13 # Vladislav Tembekov Fixed incorrect priv group assignment
# V8.2   2012-05-17 # Vladislav Tembekov Fixed incorrect SUDO privilege assignment
# V8.2.1 2012-07-24 # Vladislav Tembekov Added labeling LDAP IDS in autoldap mode
# V8.2.2 2012-08-30 # Vladislav Tembekov Added check user state on tru64
# V8.2.3 2012-09-18 # Vladislav Tembekov Added --ldapf switch
# V8.2.4 2012-09-28 # Vladislav Tembekov Added check belonging user to a group 
# V8.2.5 2012-09-28 # Vladislav Tembekov Added filter of NIS users
# V8.2.6 2012-11-16 # Vladislav Tembekov Improved check user state on AIX
# V8.2.7 2012-11-16 # Vladislav Tembekov Fixed parsing sudoers include directive
# V8.2.8 2013-02-01 # Vladislav Tembekov Improved GSA identification
# V8.2.9 2013-02-12 # Vladislav Tembekov Added processing wildcards in host_alias name of sudoers files
# V8.3.0 2013-03-01 # Vladislav Tembekov Added new pattern for account_locked values "yes" and "always"
# V8.3.1 2013-03-13 # Vladislav Tembekov Changed checking existence of ldapsearch on AIX
# V8.3.2 2013-03-28 # Vladislav Tembekov Fixed incorrect SUDO privilege issue 
# V8.3.3 2013-05-15 # Vladislav Tembekov Changed regexp to determine if user is an IBM user, fixed printing user ID as privileged if GID < 100 on Linux
# V8.3.4 2013-05-28 # Vladislav Tembekov Extended list of privileged users and groups
# V8.3.5 2013-06-05 # Vladislav Tembekov Fixed issue with "ALL" hostname in sudoers file
# V8.3.6 2013-07-15 # Vladislav Tembekov Added trim #includedir directive of sudoers file 
# V8.3.7 2013-07-18 # Vladislav Tembekov Additional check of ssh
# V8.3.8 2013-08-21 # Vladislav Tembekov Fixed incorrect argument assignment of --nis switch  
# V8.3.9 2013-11-04 # Vladislav Tembekov Improved GSA identification
# V8.4.0 2013-11-05 # Vladislav Tembekov mef4 support implemented
# V8.4.1 2013-11-18 # Vladislav Tembekov Added Vintela support
# V8.4.2 2013-11-27 # Vladislav Tembekov Changed privilege user check for RedHat and Debian
# V8.4.3 2014-02-18 # Vladislav Tembekov Rewrite code to check user state on AIX
# V8.4.4 2014-04-04 # Vladislav Tembekov Added Vintela check user state
# V8.4.5 2014-04-09 # Vladislav Tembekov Fixed compare hostnames while parsing sudoers file issue 
# V8.4.6 2014-05-03 # Vladislav Tembekov Improved Vintela check user state
# V8.4.7 2014-05-15 # Vladislav Tembekov Fixed incorrect assignment LDAP user prefix
# V8.4.8 2014-05-26 # Vladislav Tembekov Centrify support implemented
# V8.4.9 2014-06-26 # Vladislav Tembekov Added processing local users in vintela mode
# V8.5.0 2014-08-04 # Vladislav Tembekov Added timezone info in output file
# V8.5.1 2014-09-04 # Christopher Short  Added regex statements to remove the prefix that are returned during the vastool user 
#                   #                    and group lists from the ABC environment. Changed "vastool list users" command to "vastool list users-allowed"
#                   #                    so the list of users fetched from AD contain only the users relevant to the host the script is executed on.
#                   #                    also added sed statement to strip out prefix when the tmp sudoers file is created
# V8.5.2 2014-09-10 # Vladislav Tembekov Added Centrify user state checking
# V8.5.3 2014-09-29 # Vladislav Tembekov Improved GSA groups extraction form sudo file
# V8.5.4 2014-11-13 # Vladislav Tembekov Fixed incorrect variable name
# V8.5.5 2014-11-17 # Vladislav Tembekov Added possibility to change user filter in LDAP query 
# V8.5.6 2014-11-25 # Vladislav Tembekov Added code to avoid replace gecos fileld when description field has data
# V8.5.7 2014-12-10 # Vladislav Tembekov Changed regexp to check existence of user password on AIX
# V8.5.8 2015-01-12 # Vladislav Tembekov Update UNIX Extractors to report sudo privilege *access* using "user token(s)" from command allocation stanza.
# V9.0.1 2015-01-26 # Vladislav Tembekov Update version for all OS scripts. Realign numbering of perl, korn shell and bash scripts.
# V9.0.2 2015-02-23 # Vladislav Tembekov Changed vastool cmdline to list all groups from AD
# V9.0.3 2015-02-26 # Vladislav Tembekov Changed regexp to check GSA config
# V9.0.5 2015-03-06 # Vladislav Tembekov Fixed timezone issue on HP
# V9.0.6 2015-04-09 # Vladislav Tembekov Added path to ldapsearch command to LDAPPARAM file
# V9.0.7 2015-04-09 # Vladislav Tembekov Remove Case sensitivity compare LDAP host attribute
# V9.0.8 2015-06-04 # Vladislav Tembekov Fixed issue reporting user state on AIX
# V9.0.9 2015-07-02 # Vladislav Tembekov Added --signature switch for custom signature
# V9.1.0 2015-08-06 # Vladislav Tembekov Hide LDAP password
# V9.1.1 2015-08-12 # Vladislav Tembekov Add error code to the signature record of MEF3/MEF4
# V9.1.2 2015-08-13 # Vladislav Tembekov Added duplicate userid and group check
# V9.1.3 2015-08-21 # Vladislav Tembekov Fixed issue in istheredir function
# V9.1.4 2015-09-24 # Vladislav Tembekov Optimized LDAP connection check
# V9.1.5 2015-12-11 # Vladislav Tembekov Fixed duplicate local UID finding issue
# V9.1.6 2015-12-14 # Vladislav Tembekov Set priority to GECOS field while extracting user data from AD 
# V9.1.7 2016-01-15 # Vladislav Tembekov Support VIO
# V9.1.8 2016-01-28 # Vladislav Tembekov Improved LDAP user password extracting
# V9.1.9 2016-02-09 # Vladislav Tembekov R000-753 Global Unix OS - check for duplicate IDs and get data from first entry
# V9.2.0 2016-02-24 # Vladislav Tembekov Update UNIX Extractor to be compliant with latest security tech spec version V4.0
# V9.2.1 2016-03-11 # Vladislav Tembekov Update collect user states algorithm
# V9.2.2 2016-04-11 # Vladislav Tembekov Skip netgroup id from passwd file while lists local users
# V9.4.0 2016-11-10 # Vladislav Tembekov Update Global Unix Extractor to provide additional information when dealing with LDAP/NIS environments for consumption by UAT
# V9.4.1 2017-02-09 # Balagopal R Kalluri  Implemented restriction for "-uat" flag, which is not possible to use among with "-centrify" and "vintela" switches.
# V9.4.2 2017-02-13 # Balagopal R Kalluri  Fixed non-privilege IDs are extract as privilege ID.
# V9.4.3 2017-02-23 # Balagopal R Kalluri  Version change - for unique one for all 6 scripts
# V9.4.4 2017-02-13 # Balagopal R Kalluri  Fixed non-privilege IDs are extract as privilege ID and User state for VIO server issue .
# V9.4.5 2017-06-14 # Balagopal R Kalluri  Implemented code for LDAP support TLS certificate R000-895(003952fiR) .
# V9.4.6 2017-11-29 # Balagopal R Kalluri  Fixed Accounts incorrectly reported as Enabled on VIO issue(004216ilP).
# V9.4.7 2018-02-19 # Balagopal R Kalluri  Done fixes required for R000-891 requirement
# V9.4.8 2018-02-19 # Balagopal R Kalluri  Fixed version 9.4.6 causing for server hang due to recursive loop(004839zkP).
# V9.4.9 2018-07-30 # Balagopal R Kalluri  Fixed check sum space issue(005023dnP)
# V9.5.0 2018-08-06 # Balagopal R Kalluri  Implemented auto-detection of vintela(R000-684).
# V9.5.1 2018-08-02 # Balagopal R Kalluri  Fixed TLS issue(004981fjP)
# V9.5.2 2018-09-09 # Balagopal R Kalluri  R000-683,R000-685 - Implemented auto-detection of NIS and Centrify
# V9.5.3 2019-05-06 # Balagopal R Kalluri  005390shP - fixed the issue to auto detect nisplus
# V9.5.4 2019-06-24 # Balagopal R Kalluri  005459opP,005447heP,005257foP - Privileges not extracted in mef3 file for privilege users
# V9.5.5 2019-06-26 # Balagopal R Kalluri  Fixed Cloud appscan vulnerability issues.
# V9.5.6 2019-11-26 # Balagopal R Kalluri  Updated the privilege definitions of ExtractorTool as per Policy Tech spec(004877lpQ)
# V9.5.7 2019-11-29 # Balagopal R Kalluri  R001-168:Changed Last logon date format to YYYYMMDD and Added Last Expiry date field in to MEF3 file
# V9.5.8 2020-02-27 # Balagopal R Kalluri  R001-168:Added last password change attribute and mef3x switch with ON_ON,ON_OFF,OFF_OFF values.
# V9.5.9 2020-03-17 # Balagopal R Kalluri  R001-168:Added reliability check for lastlogon date and last password change date.
# V9.6.0 2020-06-04 # Balagopal R Kalluri  005071aoP: Fixed LDAP user state issue.
# V9.6.1 2020-07-30 # Balagopal R Kalluri  006100gxP,005890exP: Fixed Centrify auto detection issue
# V9.6.2 2020-08-18 # Balagopal R Kalluri  R001-154: Added unix extractor to support the  feature to report NIS+ group for local IDs 
# V9.6.3 2020-12-23 # Balagopal R Kalluri  R001-216: Modified UNIX global extractor to support Red Hat Identity Manager
# V9.6.4 2020-12-18 # Balagopal R Kalluri  R001-226: UNIX Extractors make LDAP/<group>, NIS/<group> denotation (aka UAT mode) the default MEF3 behavior.
# V9.6.5 2020-12-24 # Balagopal R Kalluri  006261zzP:Modified the extractor to report enable when NP set in /etc/shadow file
# V9.7.0 2020-02-15 # Chethan R            R001-134:Enhance UNIX extractor to handle Red Hat Linux Domain DAC, RBAC with ID Manager or ipa.
# V9.8.0 2020-03-17 # Balagopal R Kalluri  R000-769 IDEX: UNIX: Extend compatibility to Kerberos integrated AD IAA
# V9.8.1 2020-03-17 # Balagopal R Kalluri  Fixed finger command hanging issue
# V10.0.0 2021-06-15 # Balagopal R Kalluri R12-Default customer name changed from IBM  to Kyndryl and ibmOnly parameter changed to kyndrylOnly parameter.
# V10.0.1 2021-10-19 # Balagopal R Kalluri Fixed issue related to kerberos IDs.
# V10.1.0 2021-10-13 # Balagopal R Kalluri Removed code for tru64 Platform as its discontinued.
# V10.1.1 2021-12-14 # Balagopal R Kalluri Fixed user state issue for AIX servers
# V10.2.0 2022-01-20 # Balagopal R Kalluri #331 Fixed issue with kyndrylOnly switch listing all IDs.
# V10.2.1 2022-07-14 # Balagopal R Kalluri Fixed extractor to disable TLS when RHIM is enable
# V10.3.0 2022-07-14 # Balagopal R Kalluri Same version for all scripts.
# V10.3.1 2022-10-25 # Balagopal R Kalluri #786 LDAP IDs user state fix.
# V10.3.2 2022-10-25 # Balagopal R Kalluri # Fixed ldapsearch command hanging issue.
# V10.4.0 2022-10-25 # Balagopal R Kalluri #808 Fixed extracter to report userIDs which are having all special chars for KERB IDs
# V10.4.1 2023-05-17 # Balagopal R Kalluri #985 last logon date format issue got fixed for solaris servers.
# V10.4.2 2023-05-17 # Balagopal R Kalluri #963 Fixed LDAP user state issue.
# V10.5.0 2023-05-17 # Balagopal R Kalluri #109 report platform field as Linux-PHOTON for PHOTON OS systems.
# V10.6.0 2023-05-17 # Balagopal R Kalluri #1002 Added extractor to support LDAP server without passing server details.
# V10.6.1 2023-08-01 # Balagopal R Kalluri #1109 Fixed photon reporting issue.
# V10.6.2 2023-09-27 # Balagopal R Kalluri #1127,#770 Fixed last logon format for solaris servers.
# V10.6.3 2023-12-13 # Balagopal R Kalluri #1193 Fixed nslookup hanging issues.
# V10.6.4 2023-12-13 # Balagopal R Kalluri Fixed TLS related issues
# V10.7.0 2024-02-20 # Balagopal R Kalluri Added extractor to support Oracle Unified LDAP.
# V10.7.1 2024-03-26 # Balagopal R Kalluri Added return code 8, it reports when user runs the extractor without root level access.
# V10.7.2 2024-03-26 # Balagopal R Kalluri Added more warning messagse when the user ran witout root level access.
# V10.8.0 2024-04-26 # Balagopal R Kalluri Added extractor to get last logon date for VIO servers from last command.
# V10.9.0 2024-07-23 # Balagopal R Kalluri #1341 Fixed extractor to extract userstate for VIO servers from lsuser command output.
										   #1127,1415 date format fixed for SUNOS servers.
# V11.0.0 2024-10-23 # Balagopal R Kalluri #1510 Extractor to run with ON_ON by default.
# V11.0.1 2024-10-23 # Balagopal R Kalluri #1539 Added field in signature line to identify whether MEF3 generated with sudo access or not.
# V11.1.0 2024-10-23 # Balagopal R Kalluri #132 Added new parameter to extract except customerIDs.
# V11.2.0 2025-04-24 # Balagopal R Kalluri #1623 Fixed extractor to report correct last logon date for VIO servers.
# ==========================================================================================================================

# Modules
use File::Basename;
use Cwd qw(abs_path);
use POSIX qw(strftime);
use IO::File;
use Time::Local;

# Version
$VERSION='V11.2.0';

$ErrCnt=0;

#===============================================================================
# logging 
#===============================================================================
use constant INFO  => 0;
use constant DEBUG => 1;
use constant WARN  => 2;
use constant ERROR => 3;

use constant YES   => "yes";
use constant NO    => "no";

use constant EXTRACTOR_NAME => "IAM Global";

use constant EXEC_OK    => 0;
use constant EXEC_WARN  => 1;
use constant EXEC_ERR   => 2;
use constant EXEC_ABORT => 9;

use constant SEC_PER_DAY=> 86400;

my @msgType =("INFO", "DEBUG", "WARN", "ERROR");
my $STARTTIME = `date +%Y-%m-%d-%H.%M.%S`;
my $NOTROOT =0;
my $knowpar;
my $unknowpar;
my $CKSUM="";
my $KRB5AUTH;
my $OSNAME="";
my $RHIM="";
my $KERB="";
my $KGrp="";
my $KERBFlag=0;
my $LDAPNULL=0;
my $Kuid="";
my $OULD=0;
my $KERBCONF="/etc/security/access.conf";
my @Kgroups;
my $Ktmpfile="/tmp/Kiamtemp";
my $Otmpfile="/tmp/Oiamtemp";
my $Ktmpfile1="/tmp/Kiamtemp1";
my @KerbMem=();
my @AllLGroups=();
my @Pusers=();
my @LUNames=();
my $NOAUTOLDAPENABLE = 0;
my $current_id = 0;
sub chksum
{
  my $oldEnv="";
    
  open CS, "cksum '$0'|";
  while (<CS>)
  {
    chomp();
    $CKSUM = $_;  
  }
  if ( $CKSUM =~ m/^[0-9]+/ )
  {
    $CKSUM = $&
  } 
  
}

sub logMsg
{
  my $level=shift;
  my @msg=@_;
  if(INFO <= $level && $level <= ERROR)
  {
    print "[$msgType[$level]] ";
    print @msg;
    print "\n";
  }
  else
  {
    print "Wrong message level\n";
  }
  
  if( $level == WARN )
  {
    $EXIT_CODE = EXEC_WARN;
  }
}

sub logDebug
{
  if($DEBUG)
  {
    logMsg(DEBUG,@_);
  }
}

sub logInfo
{
  logMsg(INFO,@_);
}

sub logDiv
{
  logMsg(INFO, "===========================================");
}

sub logMsgVerNotSupp
{
  logMsg(ERROR, "The found version of the Sub System is not supported by the given script.");
}

sub logMsgToolNotFound
{
  logMsg(ERROR, "The following file has not been found: @_");
}

sub logAbort
{
    logMsg(ERROR,@_);
    $EXIT_CODE=EXEC_ABORT;
    logFooter();
    exit $EXIT_CODE;
}

sub logKnownArg
{
  my $optname = shift;
  my $optval =  shift;
  
  $knowpar=$knowpar."$optname $optval# ";
}

sub logUnknownArg
{
  my $optname = shift;
  if(defined $unknowpar)
  {
    $unknowpar=$unknowpar.", ";
  }
  $unknowpar=$unknowpar."$optname";
}

sub logHeader
{
  chksum;
  chomp($STARTTIME);  
  
  logMsg(INFO,"UID EXTRACTOR EXECUTION - Started");
  
  logMsg(INFO,"START TIME: $STARTTIME");
  logDiv;
  logMsg(INFO,EXTRACTOR_NAME," Extractor");
  logDiv;
}

sub logPostHeader
{
  if(defined ($knowpar))
  {
    logMsg(INFO,"Following parameters will be processed: $knowpar");
  }
  if(defined ($unknowpar))
  {
    logMsg(WARN,"Following unknown parameters will not be processed: $unknowpar");
  }
  logDiv;

  logMsg(INFO,"SCRIPT NAME: $0");
  logMsg(INFO,"SCRIPT VERSION: $VERSION");
  logMsg(INFO,"CKSUM(unix): $CKSUM");
  logMsg(INFO,"PERL VERSION(unix,pl): $]");
  logMsg(INFO,"OS CAPTION: $OSNAME");
  my $OSVER=`uname -v`;
  my $SUBVER=`uname -r`;
  chomp($OSVER);
  chomp($SUBVER);
  if($OSNAME =~/AIX/)
  {
    logMsg(INFO,"OS VERSION: $OSVER.$SUBVER");
  }
  else
  {
    logMsg(INFO,"OS VERSION: $SUBVER");
  }
  logMsg(INFO,"HOSTNAME: $HOSTNAME");
  logMsg(INFO,"CUSTOMER: $URTCUST");
  logMsg(INFO,"OUTPUTFILE: $OUTFILE");
  my $SIG="";
  if($SIG_TSCM)
  {
    $SIG="TSCM";
  }
  
  if($SIG_SCR)
  {
    $SIG="SCR";
  }
  
  if($SIG_TCM)
  {
    $SIG="TCM";
  }
  
  if($SIG_FUS)
  {
    $SIG="FUS";
  }

  logMsg(INFO,"SIGNATURE: $SIG");
  logMsg(INFO,"IS_AG: no");
  logMsg(INFO,"IS_ALLUSERIDS: YES");
  logMsg(INFO,"MEF3X: $Dormant");
  logMsg(INFO,"IS_FQDN: ", $FQDN==0 ? NO : YES);
  logMsg(INFO,"IS_DEBUG: ",$DEBUG==0 ? NO : YES);
  logMsg(INFO,"IS_ROOT: ",$NOTROOT==0 ? YES : NO);
#TLS
  logMsg(INFO,"TLS: ",$TLS==0 ? NO : YES);
  logDiv;
  logMsg(INFO,"EXTRACTION PROCESS - Started");
  if($DEBUG)
  {
    logDiv();
  }
}

sub logFooter
{
  if($DEBUG)
  {
    logDiv();
  }
  logMsg(INFO,"EXTRACTION PROCESS - Finished");
  logDiv;
  my $diff = time() - $^T;
  logMsg(INFO,"Time elapsed: $diff second", $diff > 1 ? "s" : "" );
  logDiv;
  if($NOTROOT == 1) {
 	logMsg(INFO,"The report has been finished with success"); 
  	logMsg(INFO,"General return code: ", 8);
	logMsg(INFO,"Return code 8 means Script not executed with root privileges,Running the script less than this level of access does not guarantee the ability to extract all required user data.So we recommend to run the script with root level access to get all user ID data with accuracy");
	
  } else {
 	logMsg(INFO,"The report has been finished with",$EXIT_CODE > EXEC_WARN ? "out" : ""," success"); 
  	logMsg(INFO,"General return code: ", $EXIT_CODE);
  }
  logMsg(INFO,"UID EXTRACTOR EXECUTION - Finished");
  if($EXIT_CODE > EXEC_WARN)
  {
    `rm -f $OUTFILE`
  }
}

sub removeIt
{
  print("-------------------------Debug code, remove it-----------------------------------\n"); 
}

sub glob2pat
{
 my $globstr = shift;
 my %patmap = (
    '*' => '.*',
    '?' => '.',
    '[' => '[',
    ']' => ']',
    );
 $globstr =~ s{(.)} { $patmap{$1} || "\Q$1" }ge;
 return '^' . $globstr . '$';
}

#args MM DD YY
sub formatDate
{
  my $MM=shift;
  my $DD=shift;
  my $YY=shift;
  my %monthnames = ('Jan', 01, 'Feb', '02', 'Mar', '03', 'Apr', 04, 'May', 05, 'Jun', 06, 'Jul', 07, 'Aug', '08', 'Sep', '09', 'Oct', 10, 'Nov', 11, 'Dec', 12 );
  my $MMM=$monthnames{$MM};

  return "20$YY$MMM$DD";
}

sub CleanHashes
{
  # cleaning of hashes
  while(($key, $value) = each %user_privuser){
    delete($user_privuser{$key});
  };

  while(($key, $value) = each %user_gid){
    delete($user_gid{$key});
  };

  while(($key, $value) = each %user_uid){
    delete($user_uid{$key});
  };

  while(($key, $value) = each %user_gecos){
    delete($user_gecos{$key});
  };

  while(($key, $value) = each %gmembers){
    delete($gmembers{$key});
  };

  while(($key, $value) = each %primaryGroupUsers){
    delete($primaryGroupUsers{$key});
  };

  while(($key, $value) = each %group){
    delete($group{$key});
  };

  while(($key, $value) = each %ggid){
    delete($ggid{$key});
  };

  while(($key, $value) = each %user_allgroups){
    delete($user_allgroups{$key});
  };

  while(($key, $value) = each %user_privgroups){
    delete($user_privgroups{$key});
  };
  
  while(($key, $value) = each %user_home){
    delete($user_home{$key});
  };
  
  while(($key, $value) = each %AliasList){
    delete($AliasList{$key});
  };

  while(($key, $value) = each %UserAliasList){
    delete($UserAliasList{$key});
  };

  while(($key, $value) = each %AliasOfAlias){
    delete($AliasOfAlias{$key});
  };

  while(($key, $value) = each %User_List){
    delete($User_List{$key});
  };

  while(($key, $value) = each %UserAlias){
    delete($UserAlias{$key});
  };
}

sub FinalCleanHashes
{ 
  while(($key, $value) = each %user_state){
    delete($user_state{$key});
  };

  while(($key, $value) = each %scm_user_state){
    delete($scm_user_state{$key});
  };

  while(($key, $value) = each %local_users){
    delete($local_users{$key});
  };

  while(($key, $value) = each %local_groups){
    delete($local_groups{$key});
  };

  while(($key, $value) = each %PWMinAge_Arr){
    delete($PWMinAge_Arr{$key});
  };
  
  while(($key, $value) = each %PWMaxAge_Arr){
    delete($PWMaxAge_Arr{$key});
  };

  while(($key, $value) = each %PWExp_Arr){
    delete($PWExp_Arr{$key});
  };

  while(($key, $value) = each %PWMinLen_Arr){
    delete($PWMinLen_Arr{$key});
  };

  while(($key, $value) = each %PWNeverExpires_Arr){
    delete($PWNeverExpires_Arr{$key});
  };

  while(($key, $value) = each %PWMaxExpired_Arr){
    delete($PWMaxExpired_Arr{$key});
  };

  while(($key, $value) = each %AIX_user_state){
    delete($AIX_user_state{$key});
  };

  while(($key, $value) = each %AIX_passwd_state){
    delete($AIX_passwd_state{$key});
  };

  while(($key, $value) = each %PWChg_Arr){
    delete($PWChg_Arr{$key});
  };

  while(($key, $value) = each %PWLastUpdate){
    delete($PWLastUpdate{$key});
  };
  
}

sub LoadPrivfile
{
  my $privfile = shift;
  if($privfile ne "")
  {
    logDebug("Load PRIVFILE: $privfile");
    open PRIVFILE, $privfile || logAbort("Can't open PRIVFILE: $privfile : $!");
    while($line=<PRIVFILE>)
    {
      chomp $line;
      if($line=~ /.*=.*/)
      {
        ($role, $role_name)=$line=~/^\s*(\S+)\s*=\s*\"(.*)\"\s*$/;
        if($role ne "" && $role_name ne "")
        {
          $ROLE{$role} = $role_name;
          logDebug("Add role $role, role name $role_name");
          $role = "";
          $role_name = "";
        }
        else
        {
          logDebug("Skip line: $line");
        }
      }
      else
      {
        ($readgroup)=$line=~/^\s*(\S+)\s*$/;
        if($readgroup ne "")
        {
          if($PRIVGROUPS ne "")
          {
            $PRIVGROUPS.="|";
          }
          $PRIVGROUPS.="^".$readgroup."\$";
          logDebug("Add privgroup: $readgroup");
          $readgroup="";
        }
        else
        {
          logDebug("Skip line: $line");
        }
      }
    }
  }
  logDebug("LoadPrivfile:PRIVGROUPS $PRIVGROUPS");
  close PRIVFILE;
}

#===============================================================================
# Main process flow
#===============================================================================
$EXIT_CODE=EXEC_OK;
$OSNAME=`uname`;
chomp($OSNAME);

if($OSNAME =~ /aix/i)
{
  if ( -e "/usr/ios/cli/ioscli" )
  {
    logDebug("VIO");
    $OSNAME="VIO";
  }
}

logHeader();
chomp ($current_id = `id -u`);
if ($current_id != 0) {
	$NOTROOT=1;
	logMsg(WARN,"********* Script not executed with root privileges,Running the script less than this level of access does not guarantee the ability to extract all required user data.So we recommend to run the script with root level access to get all user ID data with accuracy *********");
}

&init();
&openout();
if( $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0) {
    	logInfo("Starting auto detection of NIS");
	&auto_detect_nis();
}
if( $IS_ADMIN_ENT_ACC == 2 ) {
    	logInfo("User passed the Vintela parameter,So auto detecting of vintela is not Enabled");
} else {
    	logInfo("Starting auto detection of vintela");
	&auto_detect_vintela();
}
if( $IS_ADMIN_ENT_ACC ==3 ) {
    	logInfo("User passed the Centrify parameter,So auto detecting of centrify is not Enabled");
} else {
    	logInfo("Starting auto detection of centrify");
	&auto_detect_centrify();
}
#V9.7.0 added
if($OSNAME =~ /Linux/i) {
        logInfo("Starting auto detection of rhel idm-ipa for rbac");
        auto_detect_rhel_idm_ipa_rbac();
}
logPostHeader();

$ADMENTPASSWD = "/tmp/adment_passwd";
$ADMENTNISPASSWD = "/tmp/adment_nispasswd";
$ADMENTGROUP = "/tmp/adment_group";
$ADMENTNISGROUP = "/tmp/adment_nisgroup";
$ADMENTSPASSWD = "/tmp/adment_spasswd";

$PROCESSLDAP=0;
$PROCESSNIS=0;

$GSACONF="/usr/gsa/etc/gsa.conf";
$LDAPCONF="/etc/ldap.conf";

&get_group_info;
&get_passwd_ids;
&get_state_info;

if($NOGSA == 0 && &checkGSAconfig() == 1)
{
  if($OSNAME =~ /aix/i || $OSNAME =~ /solaris/i || $OSNAME =~ /sunos/i)
  {
    $LDAPCMD = "/usr/gsa/bin/ldapsearch";
  }
  else
  {
    $LDAPCMD = "/usr/bin/ldapsearch -x";
  }
  
  $NOAUTOLDAP=1;
  $LDAPPASSWD="/tmp/ldappasswd";
  $LDAPGROUP="/tmp/ldapgroup";

  &collectGSAusers();
  $PROCESSLDAP=1;
  $LDAP=1;  
  &parsepw();
  &parsegp();
  
  if($OSNAME !~ /aix/i)
  {
    $LDAP=0;
    $PROCESSLDAP=0;
    &parsegp();
    $LDAP=1;
    $PROCESSLDAP=1;
  }

  &parsegp();
  &parsesudoers();
  &report();
  
  $LDAP=0;  
  
  `rm -f $LDAPPASSWD`;
  `rm -f $LDAPGROUP` ;

  CleanHashes();

  $NIS=0;
  $LDAP=0;
}

if ($NIS)
{
  $IS_NISPLUS = &check_nisplus();
  if($DEBUG)
  {
    if($IS_NISPLUS)
    {
      logInfo("Processing NIS+");
    }
    else
    {
      logInfo("Processing NIS");
    }
  }
  
  $PROCESSNIS = 1;
  
  &parsepw();
  &parsegp();
  
  $NIS=0;
  $PROCESSNIS=0;
  &parsegp();
  $NIS=1;
  $PROCESSNIS=1;
  
  &parsesudoers(); # for NIS's accounts we must extract all data from SUDO-settings
  &report();

  CleanHashes();
}

$PROCESSNIS = 0;
if ($LDAP == 1 && $IS_ADMIN_ENT_ACC == 1)
{
  if(&checkforldappasswd())
  {  
  $PROCESSLDAP=1;
  $LDAPPASSWD="/tmp/ldappasswd";
  $LDAPGROUP="/tmp/ldapgroup";
  
  logInfo("Processing LDAP");
  
  collect_LDAP_users_aix();  
  &process_LDAP_users();
  &parsepw();
  get_ldgrp();
  &parsegp();

  if($OSNAME !~ /aix/i)
  {
    $LDAP=0;
    $PROCESSLDAP=0;
    &parsegp();
    $LDAP=1;
    $PROCESSLDAP=1;
  }
  &parsesudoers();
  &report();
  `rm -f $LDAPPASSWD`;
  `rm -f $LDAPGROUP` ;
  
  CleanHashes();  
}
}
$PROCESSLDAP=0;

logInfo("Processing local IDs");

if (!$NIS)
{

	&parsepw();
	&parsegp();
	&parsesudoers();

	&get_vintela_state();
	&get_centrify_state();

	&report();
}
&printsig();
logFooter();

CleanHashes();
FinalCleanHashes();
#===============================================================================
# Subs
#===============================================================================
sub help
{
print "Options Help:\n";
print "Version: $VERSION\n";
print "Optional overrides:\n";
print "--customer <customer name>\n";
print "--passwd   <passwd_file>\n";
print "--shadow   <shadow_passwd_file>\n";
print "--group    <group_file>\n";
print "--secuser  <aix_security_user_file>\n";
print "--hostname <hostname>\n";
print "--os       <operating_system_name>\n";
print "--outfile  <output_file>\n";
print "--sudoers  <sudoers_file>\n";
print "--scm\n";
print "--mef\n";
print "--privfile  <additional _priv_group_file>\n";
print "--tscm\n";
print "--rhim\n";
print "--scr\n";
print "--tsm\n";
print "--fus\n";
print "--ldap  <LDAP SERVER Name/IP:port:BASE_DN>\n";
print "--kerb  <LDAP SERVER Name/IP:BASE_DN>\n";
print "--ldapf <filename>\n";
print "--nis <directory>\n";
print "--vintela <regexp>\n";
print "--fqdn\n";
print "--noautoldap\n";
print "--customerOnly\n";
print "--kyndrylOnly\n";
print "--exceptcustomerids\n";
print "--owner <owner IDs>\n";
print "--mef3x <Dormant values>\n";
print "--dlld\n";
print "--nogsa\n";
print "--tls\n";
print "\n";
print "Options Notes:\n";
print "--passwd, --shadow, --group, --secuser, --sudoers\n";
print "Use these options for running the extract\n";
print "against files copied from one system\n";
print "to another.\n";
print "You might do this if perl is not available\n";
print "on the target system. Or for testing.\n";
print "\n";
print "--customer\n";
print "Specify the customer name\n";
print "\n";
print "--hostname\n";
print "Specify the hostname to appear in the outfile.\n";
print "This is useful when system is known\n";
print "by a name different to the system hostname.\n";
print "Or when extract is run on a different\n";
print "system e.g. when files have been copied.\n";
print "\n";
print "--os\n";
print "Use when extract is run on a system with\n";
print "a different operating system to the input\n";
print "files.(aix|hpux|sunos|linux)\n";
print "e.g. --os aix\n";
print "\n";
print "--outfile\n";
print "The default outfile is /tmp/<iam_customer_name>_<date>_<hostname>.mef3\n";
print "You can change the path/name if required.\n";
print "\n";
print "--scm\n";
print "Change output file format to scm9, instead of mef3\n";
print "\n";
print "--mef\n";
print "Change output file format to mef2, instead of mef3\n";
print "\n";
print "--mef4\n";
print "Change output file format to mef4, instead of mef3\n";
print "\n";
print "--privfile\n";
print "Additional Privilege Group file(One group per line in file)\n";
print "\n";
print "--rhim\n";
print "Uses to Enable Redhat Identity Manager\n";
print "\n";
print "--tscm\n";
print "Uses the TSCM signature\n";
print "\n";
print "--scr\n";
print "Uses the SCR signature\n";
print "\n";
print "--tsm\n";
print "Uses the TSM signature\n";
print "\n";
print "--fus\n";
print "Uses the FUS signature\n";
print "\n";
print "--ldap\n";
print "To fetch the User IDs from LDAP Server\n";
print "\n";
print "--kerb\n";
print "To fetch the User IDs from Kerberos Server\n";
print "\n";
print "--ldapf\n";
print "To fetch the User IDs from LDAP Server\n";
print "\n";
print "--nis\n";
print "To fetch the User IDs from NIS Server\n";
print "\n";
print "--vintela\n";
print "To fetch the User IDs from LDAP Server using Vintela\n";
print "\n";
print "--centrify\n";
print "To fetch the User IDs from LDAP Server using Centrify\n";
print "\n";
print "--fqdn\n";
print "FQDN format will be used in the MEF output\n";
print "\n";
#TLS
print "--tls\n";
print "support LDAP TLS certificate\n";
print "\n";
print "--noautoldap\n";
print "To fetch only local User IDs when server is LDAP connected (Linux and Solaris)\n";
print "--customerOnly\n";
print "Flag to indicate if only Customer userID's should be written to the output\n";
print "--kyndrylOnly\n";
print "Flag to indicate if only Kyndryl userID's should be written to the output\n";
print "--exceptcustomerids\n";
print "Flag to exclude Customer userID's and rest of the IDs should be written to the output\n";
print "--owner\n";
print "Flag to set the owner of the output file\n";
print "--mef3x\n";
print "Flag to set Dormant values:\non-on ... 12th attribute exists and is populated, last-login and last-password-change dates are in new standardized format. (on-on will be future default)
on-off ... 12th attribute exists but is not populated, last-login date is in new standardized format. (avoids unnecessary compute resource consumption)
off-off ... 12th attribute does not exist ... last-login-date is in legacy format (off-off is initial default to decouple AE compatibility timing) ";
print "--dlld\n";
print "Disable last logon date\n";
print "--nogsa\n";
print "Disable GSA check\n";
print "\n";
print "General Notes:\n";
print " Output is mef3 or scm9 or mef2 format including privilege data.\n";
print " List of privileged groups is hardcoded in the script\n";
print "(easy to change if required by person running the script)\n";
print " User 'state' (enabled/disabled) is extracted if possible.\n";
print " Only tested on perl v5.\n";
exit 9;
}

sub init()
{
  if ( -e "/bin/sudo" ){
    $SUDOCMD="/bin/sudo";
    chomp($SUDOVER=`$SUDOCMD -V|grep -i 'Sudo version'|cut -f3 -d" "`);
    logInfo("SUDO Version: $SUDOVER");
  }
  elsif ( -e "/usr/bin/sudo" ){
    $SUDOCMD="/usr/bin/sudo";
    chomp($SUDOVER=`$SUDOCMD -V|grep -i 'Sudo version'|cut -f3 -d" "`);
    logInfo("SUDO Version: $SUDOVER");
  }
  elsif ( -e "/usr/local/bin/sudo" ){
    $SUDOCMD="/usr/local/bin/sudo";
    chomp($SUDOVER=`$SUDOCMD -V|grep -i 'Sudo version'|cut -f3 -d" "`);
    logInfo("SUDO Version: $SUDOVER");
  }
  elsif ( -e "/usr/local/sbin/sudo" ){
    $SUDOCMD="/usr/local/sbin/sudo";
    chomp($SUDOVER=`$SUDOCMD -V|grep -i 'Sudo version'|cut -f3 -d" "`);
    logInfo("SUDO Version: $SUDOVER");
  }
  else{
    $SUDOVER="NotAvailable";
    if ($OSNAME !~ /vio/i) {
	    logMsg(WARN, "unable to get Sudo Version:$SUDOVER.");
	}
  }

  $DEV=0;
  
  # System details
  chomp($HOST=`hostname`);
  $LONG_HOST_NAME=lc $HOST;
  ($HOST,@_)= split(/\./,$HOST);
  $HOSTNAME=lc $HOST;
  
  if(scalar(@_) == 0)
  {
    $LONG_HOST_NAME=&getfqdn($HOST);
  }
  chomp($DATE=`date +%d%b%Y`);
  $DATE=uc($DATE);
  $DEBUG=0;
  $SCMFORMAT=0;
  $MEF2FORMAT=0;
  $MEF4FORMAT=0;

  #auditdate is the date of the last scm collector run corresponding to this
  #hostname in the format yyyy-mm-dd-hh.mm.ss (2006-04-02-00.00.00)..
  #yyyy-mm-dd-hh.mm.ss
  chomp($myAUDITDATE=`date +%Y-%m-%d-%H.%M.%S`);

  $uname=`uname`;
  chomp($uname);

  # Default file locations which dont depend on OS
  $URTCUST="Kyndryl";
  $PASSWD="/etc/passwd";
  $GROUP="/etc/group";
  $SUDOERS="";
  $OUTFILE = "/tmp/$URTCUST\_$DATE\_$HOST.mef3";
  $NEWOUTFILE = "";
  $PRIVFILE = "";
  $SSHD_CONFIG="/etc/ssh/sshd_config";
  $LDAP=0;
  $NIS=0;
  $FQDN=0;
  $ENABLEFQDN=1;
  $tmpfile="/tmp/iamtemp";
  $NOAUTOLDAP=0;
  $USERCC="897";
  $ibmonly=0;
  $noncustomeronly=0;
  $customeronly=0;
  $OWNER="";
  $Dormant="ON_ON";
  $LDAPARG="";
  $DLLD=0;
  $NOGSA=0;
  $LDAPFILE="";
  $LDAPBASEGROUP="";
  $LDAPGROUPOBJCLASS="";
  $LDAPADDITIONAL="";
  $NISPLUSDIR="";
  $USERSPASSWD=0;
  $USEROSNAME=0;
  $VPREFIX="";
  $SIGNATURE="";
  $IS_ADMIN_ENT_ACC=0;
  $UAT=0;
#TLS 
 $TLS=0; 
  findSudoersFile();
$RHELIDMIPA=0; #V9.7.0 added
  
  while(@ARGV)
  {
    my $opt=shift @ARGV;
    if($opt eq "--customer") {$URTCUST=shift @ARGV; logKnownArg($opt, $URTCUST); next;}
    if($opt eq "--passwd") {$PASSWD=shift @ARGV;$NOAUTOLDAP=1; logKnownArg($opt, $PASSWD); next;}
    if($opt eq "--shadow") {$SPASSWD=shift @ARGV; $USERSPASSWD=1; logKnownArg($opt, $SPASSWD); next;}
    if($opt eq "--group")  {$GROUP=shift @ARGV;$NOAUTOLDAP=1;logKnownArg($opt, $GROUP); next;}
    if($opt eq "--sudoers"){$SUDOERS=shift @ARGV;logKnownArg($opt, $SUDOERS); next;}
    if($opt eq "--secuser"){$SUSER=shift @ARGV; logKnownArg($opt, $SUSER); next;}
    if($opt eq "--hostname")
    {
      $HOSTNAME=$LONG_HOST_NAME=lc shift @ARGV;
      logKnownArg($opt, $HOSTNAME);
      $ENABLEFQDN=0;
      ($HOST,@_)= split(/\./,$LONG_HOST_NAME);
      next;
    }
    if($opt eq "--os"){$OSNAME=shift @ARGV;$USEROSNAME=1;logKnownArg($opt, $OSNAME);next;}
    if($opt eq "--debug"){logKnownArg($opt);$DEBUG=1; next;}
    if($opt eq "--scm"){logKnownArg($opt);$SCMFORMAT=1; next;}
    if($opt eq "--mef"){logKnownArg($opt);$MEF2FORMAT=1; next;}
    if($opt eq "--mef4"){logKnownArg($opt);$MEF4FORMAT=1; next;}
    if($opt eq "--privfile"){$PRIVFILE=shift @ARGV; logKnownArg($opt, $PRIVFILE);next;}
    if($opt eq "--outfile"){$NEWOUTFILE=shift @ARGV; logKnownArg($opt, $NEWOUTFILE); next;}
    if($opt eq "--tscm"){logKnownArg($opt);$SIG_TSCM=1; next;}
    if($opt eq "--scr"){logKnownArg($opt);$SIG_SCR=1; next;}
    if($opt eq "--tcm"){logKnownArg($opt);$SIG_TCM=1; next;}
    if($opt eq "--fus"){logKnownArg($opt);$SIG_FUS=1; next;}
    if($opt eq "--rhim"){logKnownArg($opt);$RHIM=1; next;}
	if($opt eq "--ldappasswd"){$LDAPPWD=shift @ARGV; logKnownArg($opt, $LDAPPWD); next;}
    if($opt eq "--signature"){$SIGNATURE=shift @ARGV; logKnownArg($opt, $SIGNATURE);next;}
    if($opt eq "--nis")
    {
      $NISPLUSDIR=shift @ARGV;
      $NISPLUSDIR=trim($NISPLUSDIR);
      if($NISPLUSDIR =~ /^--/ || $NISPLUSDIR eq "")
      {
        unshift @ARGV, $NISPLUSDIR;
        $NISPLUSDIR="";
        logKnownArg($opt);
      }
      else
      {
        logKnownArg($opt, $NISPLUSDIR);
        $NISPLUSDIR=".$NISPLUSDIR";
      }
      $NIS=1;
      $NOAUTOLDAP=1;
      next;
    }

    if($opt eq "--kerb")
    {
      $KERB=1;
      $KERBARG=shift @ARGV;
      my $KARG=$KERBARG;
      $KARG=~ s/-w\s+\S+(\s|$)/-w \*\*\*\*\*\*\*\* /;
      logKnownArg($opt, $KARG);
      next;
    }
	
	 if($opt eq "--ould")
    {
      $OULD=1;
      $OULDARG=shift @ARGV;
      my $OARG=$OULDARG;
      $OARG=~ s/-w\s+\S+(\s|$)/-w \*\*\*\*\*\*\*\* /;
      logKnownArg($opt, $OARG);
      next;
    }


    if($opt eq "--ldap")
    {
      $LDAP=1;
      $NOAUTOLDAP=1;
      $LDAPARG=shift @ARGV;
      my $KARG=$LDAPARG;
	  $KARG=~ s/-w\s+\S+(\s|$)/-w \*\*\*\*\*\*\*\* /;
      logKnownArg($opt, $KARG);
      next;
    }
	if($opt eq "--ldapn"){logKnownArg($opt);$LDAP=1;$LDAPNULL=1; logInfo("LDAPNULL Value is : $LDAPNULL");next;}
    if($opt eq "--ldapf"){$LDAP=1;$NOAUTOLDAP=1;$LDAPFILE=shift @ARGV; logKnownArg($opt, $LDAPFILE);next;}
    if($opt eq "--fqdn"){logKnownArg($opt);$FQDN=1; next;} 
    if($opt eq "--noautoldap"){logKnownArg($opt);$NOAUTOLDAP=1;$NOAUTOLDAPENABLE=1; next;}
    if($opt eq "--kyndrylOnly"){logKnownArg($opt);$ibmonly=1; next;}
	if($opt eq "--exceptcustomerids"){logKnownArg($opt);$noncustomeronly=1; next;}
    if($opt eq "--customerOnly"){logKnownArg($opt);$customeronly=1; next;}
    if($opt eq "--owner"){$OWNER=shift @ARGV; logKnownArg($opt, $OWNER);next;}
    if($opt eq "--mef3x"){
	$Dormant= uc shift @ARGV; 
	logKnownArg($opt, $Dormant);
	logDebug("Dormant switch $Dormant Passed");
	next;
	}
    if($opt eq "--dlld"){logKnownArg($opt);$DLLD=1; next;}# disable last logon date
    if($opt eq "--help"){ help(); next;}
    if($opt eq "--nogsa"){ logKnownArg($opt); $NOGSA=1; next;}
    if($opt eq "--dev"){ $DEV=1; next;}
    if($opt eq "--vintela")
    {
      $IS_ADMIN_ENT_ACC=2;
      $VPREFIX=shift @ARGV;
      $VPREFIX=trim($VPREFIX);
      if($VPREFIX =~ /^--/ || $VPREFIX eq "")
      {
        unshift @ARGV, $VPREFIX;
        $VPREFIX="";
        logKnownArg($opt);
      }
      else
      {
        logKnownArg($opt, $VPREFIX);
        $VPREFIX=$VPREFIX.'[\\92\\|\\92\\92]';
      }
      next;
    }
    if($opt eq "--centrify")
    {
       logKnownArg($opt); $IS_ADMIN_ENT_ACC=3; next;
    }
    
    if($opt eq "--uat")
    {
      logKnownArg($opt); $UAT=1; next;
    }
   #TLS 
    if($opt eq "--tls")
    {
      logKnownArg($opt); $TLS=1; next;
    }
    logUnknownArg($opt);
  }

  if($UAT == 1 && ($IS_ADMIN_ENT_ACC == 2 || $IS_ADMIN_ENT_ACC == 3))
  {
	logMsg(WARN,"--uat switch is not allowed with --centrify and --vintela,So ignoring --uat switch.");
	$UAT=0;
  }
  if($Dormant ne "" ) {
	 if ($Dormant !~ /ON_ON|ON_OFF|OFF_OFF/) {
	
		logMsg(WARN,"--mef3x switch values should be having (ON_ON,ON_OFF,OFF_OFF), Extractor won't support any other values.");
	}
  }
  &is_adminent_accessible();
  
  $DISTRVER="unknown";
  $DISTRNAME=&GetDistrName();
  if( $DISTRNAME ne "unknown")
  {
    $DISTRVER=&GetDistrVer($DISTRNAME);
  }
  logDebug("GetDistrVer: $DISTRVER");
  logDebug("GetDistrName: $DISTRNAME");
  
  if($IS_ADMIN_ENT_ACC == 3)
  {
    logInfo("Flush the Centrify and nscd cache");
    `/usr/sbin/adflush >/dev/null 2>&1`;
    logInfo("Flush completed, exit code $?"); 
  }
    
  if($DEV == 1)
  {
    logInfo("Developer mode");
  }
    
  if ($FQDN == 1 && $ENABLEFQDN == 1) {
    $HOSTNAME=$LONG_HOST_NAME;
}
  
  logDebug("init: host $HOST:$LONG_HOST_NAME");
  if( $KERB ==1 ) {
        if ( $KERBARG =~ /\S+:\S+/ ) {
                ($KERBSVR ,$KERBBASE )  = split(/\:/,$KERBARG);
        } else {
             logAbort("Invalid LDAPSVR, and LDAP BASE");
        }
   }
     if( $OULD ==1 ) {
        if ( $OULDARG =~ /\S+:\S+/ ) {
                ($OULDSVR ,$OULDPORT,$OULDBASE )  = split(/\:/,$OULDARG);
        } else {
             logAbort("Invalid LDAPSVR,LDAP PORT and LDAP BASE");
        }
     }
  
  
  if($LDAP == 1 && $LDAPNULL == 0)
  {
    $LDAPCMD="";
    if ( $LDAPARG =~ /\S+:\d+:\S+/ )
    {
      ($LDAPSVR ,$LDAPPORT,$LDAPBASE )  = split(/\:/,$LDAPARG);
    }
    elsif($LDAPFILE ne "" )
    {
        $LDAPSVR=&getFromThere($LDAPFILE,"^LDAPSVR:\\s*(.*)\$");
        $LDAPBASE=&getFromThere($LDAPFILE,"^LDAPBASEPASSWD:\\s*(.*)\$");
        $LDAPBASEGROUP=&getFromThere($LDAPFILE,"^LDAPBASEGROUP:\\s*(.*)\$");
        $LDAPPORT=&getFromThere($LDAPFILE,"^LDAPPORT:\\s*(.*)\$");
        $LDAPGROUPOBJCLASS=&getFromThere($LDAPFILE,"^LDAPGROUPOBJCLASS:\\s*(.*)\$");
        $LDAPADDITIONAL=&getFromThere($LDAPFILE,"^LDAPADDITIONAL:\\s*(.*)\$");
        $LDAPUSERFILTER=&getFromThere($LDAPFILE,"^LDAPUSERFILTER:\\s*(.*)\$");
        $LDAPCMDTMP=&getFromThere($LDAPFILE,"^LDAPCMD:\\s*(.*)\$");
        
        if($LDAPCMDTMP ne "")
        {
          $LDAPCMD=$LDAPCMDTMP;
        }
        
        if($LDAPUSERFILTER eq "")
        {
          $LDAPUSERFILTER="uid=*";
        }

        if($LDAPSVR eq "" || $LDAPBASE eq "" || $LDAPPORT eq "" || $LDAPGROUPOBJCLASS eq "" || $LDAPBASEGROUP eq "")
        {
          logAbort("Invalid $LDAPFILE, exiting");
        }
    }
    else
    {
		
      logAbort("Invalid LDAPSVR, LDAPPORT and LDAP BASE");
    }
  }
  
  
  if( $LDAPCMD eq "")
  {
    if($OSNAME =~ /aix/i || $OSNAME =~ /solaris/i || $OSNAME =~ /sunos/i)
    {
      $LDAPCMD = "ldapsearch";
      if($OSNAME =~ /aix/i)
      {
        $attr=`which $LDAPCMD 2>/dev/null`;
        if ( $? == 1 )
        {
          $LDAPCMD = "idsldapsearch";
        }
      }
    }
    else
    {
      $LDAPCMD = "ldapsearch -x";
    }
  }
  
  if($DEV == 1)
  {
    $LDAPCMD = "./ldapsearch";
  }
  
  logDebug("init: configure data for $OSNAME");
  
  # File locations which depend on OS
  for ($OSNAME)
  {
    if (/aix/i)
    {
      logDebug("Found AIX");
      $SPASSWD = $SPASSWD ? $SPASSWD : "/etc/security/passwd";
      $SUSER = $SUSER ? $SUSER : "/etc/security/user";
      # Define priv groups - this is an extended regex ie pipe separated list of things to match
   $PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^adm$|^uucp$|^nuucp$|^lpd$|^imnadm$|^ipsec$|^ldap$|^lp$|^snapp$|^invscout$|^nobody$|^notes$|^esaadmin$|^pconsole$|^srvproxy$';
      $PRIVGROUPS='^system$|^security$|^bin$|^sys$|^adm$|^uucp$|^mail$|^printq$|^cron$|^audit$|^shutdown$|^ecs$|^imnadm$|^ipsec$|^ldap$|^lp$|^haemrm$|^snapp$|^hacmp$|^notes$|^mqm$|^dba$|^sapsys$|^db2iadm1$|^db2admin$|^sudo$|^SSHD$|^sshd$|^invscout$|^pconsole$';
    }
    elsif (/vio/i)
    {
      logDebug("Found VIO");
      $SPASSWD = $SPASSWD ? $SPASSWD : "/etc/security/passwd";
      $SUSER = $SUSER ? $SUSER : "/etc/security/user";
      # Define priv groups - this is an extended regex ie pipe separated list of things to match
      $PRIVUSERS='^padmin$';
      $PRIVGROUPS='';
      $ROLE{"SYSAdm"} = "System Administrator";
      $ROLE{"SRUser"} = "Service Representative";
      $ROLE{"DEUser"} = "Development Engineer";
    }
    elsif (/hpux/i || /hp-ux/i)
    {
      logDebug("Found HPUX");
      $SPASSWD = $SPASSWD ? $SPASSWD : "/etc/shadow";
      $PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^adm$|^uucp$|^lp$|^nuucp$|^hpdb$|^imnadm$|^nobody$|^notes$|^auth$|^cron$|^ris$|^tcb$|^uucpa$|^wnn$';
      $PRIVGROUPS='^root$|^other$|^bin$|^sys$|^adm$|^daemon$|^mail$|^lp$|^tty$|^nuucp$|^nogroup$|^imnadm$|^mqm$|^dba$|^sapsys$|^db2iadm1$|^db2admin$|^sudo$|^notes$|^SSHD$|^sshd$|^auth$|^backup$|^cron$|^kmem$|^lpr$|^mem$|^news$|^operator$|^opr$|^ris$|^sec$|^sysadmin$|^system$|^tape$|^tcb$|^terminal$|^uucp$';
    }
    elsif (/sunos/i || /solaris/i)
    {
      logDebug("Found SunOS");
      $SPASSWD = $SPASSWD ? $SPASSWD : "/etc/shadow";

      if (-e "/usr/local/etc/sshd_config"){
        $SSHD_CONFIG = "/usr/local/etc/sshd_config";
      }

      $PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^adm$|^uucp$|^nuucp$|^imnadm$|^lp$|^smmsp$|^listen$|^nobody$|^notes$|^lpd$|^ipsec$|^snapp$|^invscout$|^aiuser$|^dhcpserv$|^dladm$|^ftp$|^gdm$|^ikeuser$|^mysql$|^netadm$|^netcfg$|^noaccess$|^openldap$|^pkg5srv$|^postgres$|^sms-svc$|^svctag$|^upnp$|^webservd$|^xvm$|^zfssnap$';
      $PRIVGROUPS='^system$|^security$|^bin$|^sys$|^uucp$|^mail$|^imnadm$|^lp$|^root$|^other$|^adm$|^tty$|^nuucp$|^daemon$|^sysadmin$|^smmsp$|^nobody$|^notes$|^mqm$|^dba$|^sapsys$|^db2iadm1$|^db2admin$|^sudo$|^SSHD$|^sshd$|^printq$|^cron$|^audit$|^ecs$|^shutdown$|^ipsec$|^ldap$|^haemrm$|^snapp$|^hacmp$|^cimsrvr$|^ftp$|^gdm$|^mlocate$|^mysql$|^netadm$|^noaccess$|^openldap$|^pkg5srv$|^postgres$|^root$|^slocate$|^sms $|^staff$|^upnp$|^webservd$|^xvm$';
    }
    elsif (/linux/i)
    {
      logDebug("Found Linux");
      $SPASSWD = $SPASSWD ? $SPASSWD : "/etc/shadow";
      $PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^nobody$|^notes$';
      $PRIVGROUPS='^notes$|^mqm$|^dba$|^sapsys$|^db2iadm1$|^db2admin$|^sudo$|^wheel$|^SSHD$|^sshd$';
    }
    else
    {
      logDebug("Found Unknown OS");
      $PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^adm$|^uucp$|^nuucp$|^lpd$|^imnadm$|^ipsec$|^ldap$|^lp$|^snapp$|^invscout$|^nobody$|^notes$|^hpdb$|^smmsp$|^listen$';
      $PRIVGROUPS='^1bmadmin$|^adm$|^audit$|^bin$|^cron$|^daemon$|^db2admin$|^db2iadm1$|^dba$|^ecs$|^hacmp$|^haemrm$|^ibmadmin$|^imnadm$|^ipsec$|^ldap$|^lp$|^mail$|^mqm$|^nobody$|^nogroup$|^notes$|^nuucp$|^other$|^printq$|^root$|^sapsys$|^security$|^shutdown$|^smmsp$|^snapp$|^suroot$|^sys$|^sysadm$|^system$|^tty$|^uucp$|^wheel$|^SSHD$|^sshd$|^sudo$|^sysad$|^sysadmin$';
      $SPASSWD = $SPASSWD ? $SPASSWD : "/etc/shadow";
    }
  } # end for

  logDebug("PRIVUSERS: $PRIVUSERS");
  logDebug("PRIVGROUPS: $PRIVGROUPS");

  LoadPrivfile($PRIVFILE);

  ## check to see if given a specfic outfile name
  if ($NEWOUTFILE eq "")
  {
    # update default outfile if scm
    if ($SCMFORMAT)
    {
      $OUTFILE = "/tmp/$URTCUST\_$DATE\_$HOSTNAME.scm9";
    }
    elsif ($MEF2FORMAT)
    {
      $OUTFILE = "/tmp/$URTCUST\_$DATE\_$HOSTNAME.mef";
    }
    elsif ($MEF4FORMAT)
    {
      $OUTFILE = "/tmp/$URTCUST\_$DATE\_$HOSTNAME.mef4";
    }
    else
    {
      $OUTFILE = "/tmp/$URTCUST\_$DATE\_$HOSTNAME.mef3";
    }
  }
  else
  {
    if($NEWOUTFILE =~ /\//)
    {
      $OUTFILE = $NEWOUTFILE;
    }
    else
    {
      $OUTFILE = "/tmp/"."$NEWOUTFILE";
    }
  }
  
  if($SUDOERS eq "/dev/null")
  {
    if ($OSNAME !~ /vio/i) {
		logMsg(WARN,"unable to find sudoers file.  Account SUDO privileges will be missing from extract");
	}
  }
} # end init sub

sub findSudoersFile
{
  $SUDOERS="/dev/null";
  my $SUDOERS1="/etc/sudoers";
  my $SUDOERS2="/opt/sfw/etc/sudoers";
  my $SUDOERS3="/usr/local/etc/sudoers";
  my $SUDOERS4="/opt/sudo/etc/sudoers";
  my $SUDOERS5="/opt/sudo/etc/sudoers/sudoers";
  my $SUDOERS6="/usr/local/etc/sudoers/sudoers";
  my $SUDOERS7="/opt/sudo/sudoers";

  if(-r $SUDOERS1)
  {
    $SUDOERS=$SUDOERS1
  }
  else
  {
    if(-r $SUDOERS2)
    {
      $SUDOERS=$SUDOERS2;
    }
    else
    {
      if(-r $SUDOERS3)
      {
        $SUDOERS=$SUDOERS3;
      }
      else
      {
        if(-r $SUDOERS4)
        {
          $SUDOERS=$SUDOERS4;
        }
        else
        {
          if(-r $SUDOERS5)
          {
            $SUDOERS=$SUDOERS5;
          }
          else
          {
            if(-r $SUDOERS6)
            {
              $SUDOERS=$SUDOERS6;
            }
            else
            {
              if(-r $SUDOERS7)
              {
                $SUDOERS=$SUDOERS7;
              }
            }
          }
        }
      }
    }
  }
}

sub GetDistrName
{
  my $DISTR="unknown";
  
  if($USEROSNAME == 0 && $OSNAME=~/linux/i )
  {
    if ( -e "/etc/SuSE-release")
    {
      $DISTR="suse";
    }
    elsif ( -e "/etc/debian_version")
    {
      $DISTR="debian";
    }
    elsif ( -e "/etc/redhat-release")
    {
      $DISTR="redhat";      
    }
  }
  return trim($DISTR);
}

sub GetDistrVer
{
  my $DISTR=shift;
  my $VER="unknown";
 
if($DISTR eq "redhat")
  {
	  $attr=`which lsb_release 2>/dev/null`;
        if ( $? == 0 ) {
          $VER=`lsb_release -s -r | cut -d '.' -f 1`;
		}
    if($VER eq "") {
          $VER=`cat /etc/redhat-release | sed -e 's#[^0-9.]##g' | cut -d "." -f1`;
        }
  }
 
  elsif($DISTR eq "debian")
  {
    $VER=`cat /etc/debian_version`;
  }
  elsif($DISTR eq "suse")
  {
    $VER=`cat /etc/SuSE-release | grep 'VERSION' | sed  -e 's#[^0-9]##g'`;
  }
  
  return trim($VER);
}

sub checkforldappasswd()
{
  $FPASSWD = $PASSWD;
  my $retFlag=1;
  open PASSWD_FILE, $FPASSWD || logAbort("Can't open $FPASSWD : $!");
  while ($Line = <PASSWD_FILE>)
  {
    if($Line =~ /^\+/)
    {
      $retFlag=0;
      last;
    }
  }
  close PASSWD_FILE;
  logDebug("checkforldappasswd: $retFlag");
  return  $retFlag;
}

sub get_passwd_ids
{
  open PASSWD_FILE, $PASSWD || logAbort("Can't open $PASSWD : $!");
  while (<PASSWD_FILE>)
  {
    chomp;
    logDebug("get_passwd_ids: $_");
    ($username, $passwd, $uid, $gid, $gecos, $home, $shell) = split(/:/);
    if($username eq "")
    {
      logDebug("get_passwd_ids: Skip empty user name");      
      next;
    }
    if($username =~ /^\+/)
    {
      logDebug("get_passwd_ids: Skip netgroup $username");      
      next;
    }
    if($local_users{$username} eq 1)
    {
      logMsg(WARN,"User \"$username\" already exists in $PASSWD file. Output file can be incorrect.");
      next;
    }    
    $local_users{$username}=1;
  }
  close PASSWD_FILE;
}

# groupname gid
sub is_priv_group
{
  my $groupname = shift;
  my $gid = shift;
  
  logDebug("is_priv_group: groupname $groupname, GID $gid");
  
  if ($groupname =~ /$PRIVGROUPS/)
  {
    logDebug("Found priv group $groupname");
    return 1;
  }

  if ($OSNAME=~/linux/i)
  {
    if( $gid <= 99)
    {
      logDebug("$groupname is privileged");
      return 1;
    }

    if( $DISTRNAME eq "suse" )
    {
      if( $DISTRVER >= 9 && $gid >= 101 && $gid <= 499) #SLES 10 and later - GID >= 101 and GID <= 499
      {
        logDebug("$groupname is privileged");
        return 1;
      }
    }
    elsif( $DISTRNAME eq "debian")
    {
      if( $DISTRVER == 5 && $gid >= 101 && $gid <= 199)
      {
        logDebug("$groupname is privileged");
        return 1;  
      }
      if($DISTRVER >= 6 && $gid >= 101 && $gid <= 999)
      {
        logDebug("$groupname is privileged");
        return 1;
      }
    }
    elsif( $DISTRNAME eq "redhat" ) #RHEL 7 and later - GID >= 101 and GID <= 999
    {
	if ( $gid eq "") {
         logDebug("$gid is empty so groupname is not privileged");
         return 1;
	}
       if($DISTRVER >= 5 && $gid >= 101 && $gid <= 499)
       {
         logDebug("$groupname is privileged");
         return 1;
       }
       if($DISTRVER >= 7 && $gid >= 500 && $gid <= 999)
       {
         logDebug("$groupname is privileged");
         return 1;
       }
    }   
  }
  return 0;
}

sub get_group_info
{
  open GROUP_FILE, $GROUP || logAbort("Can't open $GROUP : $!");
  while (<GROUP_FILE>)
  {
    chomp;
    logDebug("get_group_info: $_");
    ($groupname, $passwd, $gid, $userlist) = split(/:/);
    
    if($groupname =~ /^\+/)
    {
      logDebug("get_group_info: Skip group $groupname");
      next;
    }
    
    if($local_groups{$groupname})
    {
      logMsg(WARN,"Group \"$groupname\" already exists in $GROUP file. Output file can be incorrect.");
      next;
    }
    $local_groups{$groupname}=1;
    if(is_priv_group($groupname, $gid) == 1 )
    {
      $privgroups{$groupname}=1;
    }
  }
  close GROUP_FILE;
  logDebug("get_group_info: end");
}

sub parse_user_info
{
    logDebug("parse_user_info:$username:$passwd:$uid:$gid:$gecos");
    
    if($username eq "" || $uid eq "" || $gid eq "")
    {
      logDebug("parse_user_info: wrong ID $username");
      return;
    }
    
    $user_home{$username}=$home;
        
    if ($primaryGroupUsers{$gid})
    {
      $primaryGroupUsers{$gid} = $primaryGroupUsers{$gid} . "," . $username;
    }
    else
    {
      $primaryGroupUsers{$gid} = $username;
    } # end if

    if ($username =~ /$PRIVUSERS/ )
    {
      logDebug("parse_user_info: privuser found: id = $username");
      $user_privuser{$username} = $username;
    }
    $user_uid{$username} = $uid;
    $user_gid{$username} = $gid;
    $user_gecos{$username} = $gecos;
    chomp $shell;

    # check for user disabled by * in password field
    # Bypass if this is an TCB HPUX system
    if ($HPUX_TCB_READABLE == 0)
    {
      if ( $passwd =~ /^\*/ )
      {
        if ( -e $SPASSWD )
        {
          if ( $PUBKEYAUTH eq "yes" ) {                 # 7.4 Code to check SSH public key authentation status for users having password "*" in passwd file
            logDebug("Checking for public key file $home/$AUTHORIZEDKEYSFILE for user: $username");
            if (( -e "$home/$AUTHORIZEDKEYSFILE" ) || ( -e "$home/$AUTHORIZEDKEYSFILE2" ))
            {
              $user_state{$username} = "SSH-Enabled";
              logDebug("SSH key file is found:$username");
            }
            else
            {
              $user_state{$username} = "Disabled";
              $scm_user_state{$username} = "1";
            }
          }
          else
          {
            $user_state{$username} = "Disabled";
            $scm_user_state{$username} = "1";
            logDebug("$username Disabled: passwd=$passwd in passwd file");
          }
        }
        else
        {
          if($OSNAME =~ /hpux/i || $OSNAME =~ /hp-ux/i || PROCESSNIS)
          {
            $user_state{$username} = "Disabled";
            $scm_user_state{$username} = "1";
            logDebug("$username Disabled: passwd=$passwd in passwd file");
          }
        }
      }
    }
    else
    {
      logDebug("$username Bypassing check for user disabled by * in password field");
    }

         if ( $KRB5AUTH eq "yes" && ( $local_users{$username} != 1 || $PROCESSLDAP ) && ($PROCESSNIS == 0 && $IS_ADMIN_ENT_ACC == 1) && $user_state{$username} ne "SSH-Enabled") {

                      logDebug("Bypassing check for kerberos user:$username enabled by * in password field");
                      $user_state{$username} = "Enabled";
                }
		#  if ($IS_ADMIN_ENT_ACC ==1 && $local_users{$username} != 1 && $user_state{$username} ne "SSH-Enabled" ) {

		#logDebug("Bypassing check for LDAP user:$username enabled by * in password field");
		#$user_state{$username} = "Enabled";
		#}

    
    if( (! defined($user_state{$username})) || $user_state{$username} ne "SSH-Enabled")
    {
      if ( $shell =~ /\/bin\/false/ )
      {
        $user_state{$username} = "Disabled";
        $scm_user_state{$username} = "1";
        logDebug("$username Disabled: shell=$shell in passwd file");
      }
      if ( $shell =~ /\/usr\/bin\/false/ )
      {
        $user_state{$username} = "Disabled";
        $scm_user_state{$username} = "1";
        logDebug("$username Disabled: shell=$shell in passwd file");
      }
    }

    ## add users to group memberlist  array if user is no listed in its primary group
    %gmemlist=();
    if ( ! defined $gmembers{$gid} )
    {
      $gmembers{$gid} = $username;
      logDebug("$username member of $gid");
    }
    else
    {
      # add user only user not in current list
      foreach $nlist (split(/\,/,$gmembers{$gid}))
      {
        $gmemlist{$nlist}=$nlist;
      }
      if(exists $gmemlist{$username})
      {
        ## already in list
      }
      else
      {
        $gmembers{$gid} = $gmembers{$gid}.",$username";
        logDebug("Adding $username to gid:$gid user list $gmembers{$gid}");
      }
    }
}

sub parsepw()
{
  $AUTHORIZEDKEYSFILE="";
  $AUTHORIZEDKEYSFILE2="";
  $PUBKEYAUTH="";
$KRB5AUTH="";
  # check to see if this is a TCB HPUX system
  # if getprpw is found, we assume this is a TCB machine
  $HPUX_TCB_READABLE=0;
  if($OSNAME =~ /hpux/i || $OSNAME =~ /hp-ux/i)
  {
    # check to see if command is executable
    if(-x "/usr/lbin/getprpw" && -d "/tcb" )
    {
      $HPUX_TCB_READABLE=1;
    }
  }
  logDebug("HPUX_TCB_READABLE: $HPUX_TCB_READABLE");

  $SSSD_CONFIG="/etc/sssd/sssd.conf";
    open SSSD_FILE, $SSSD_CONFIG || logMsg(WARN,"Cannot open $SSSD_CONFIG file");
    while (my $Line = <SSSD_FILE>)
    {

            if ($Line =~ /auth_provider = krb5/)
            {
                $KRB5AUTH = "yes";
                logDebug("parsepw:KRB5 authentication in use");
            }
    }
    close SSSD_FILE;


  # 7.4 Code to check SSH public key authentation status for users having password "*" in passwd file
  open SSH_FILE, $SSHD_CONFIG || logMsg(WARN,"Cannot open $SSHD_CONFIG file");
  while ($Line = <SSH_FILE>)
  {
    if ($Line =~ /^AuthorizedKeysFile\s*(\S+)\s$/)
    {
      $AUTHORIZEDKEYSFILE = $1;
      logDebug("parsepw:SSH Authkey file is $AUTHORIZEDKEYSFILE");
    }
    
    if ($Line =~ /^AuthorizedKeysFile2\s*(\S+)\s$/)
    {
      $AUTHORIZEDKEYSFILE2 = $1;
      logDebug("parsepw:SSH Authkey file is $AUTHORIZEDKEYSFILE2");
    }
    
    if ($Line =~ /^PubkeyAuthentication\s*(\w+)\s$/)
    {
      $PUBKEYAUTH = $1;
      logDebug("parsepw:SSH publickey authentication enabled is $PUBKEYAUTH");
    }
  }
  close SSH_FILE;

  if ($AUTHORIZEDKEYSFILE eq "")
  {
    $AUTHORIZEDKEYSFILE=".ssh/authorized_keys";
  }

  if ($AUTHORIZEDKEYSFILE2 eq "")
  {
    $AUTHORIZEDKEYSFILE2=".ssh/authorized_keys2";
  }

  if ($PROCESSNIS)                  # V 4.5
  {
    if ($IS_NISPLUS)
   {
    `niscat passwd.org_dir$NISPLUSDIR > $ADMENTNISPASSWD`;
    `niscat group.org_dir > $ADMENTNISGROUP`;
  }
  else
  {
    `ypcat passwd > $ADMENTNISPASSWD`;
    `ypcat group > $ADMENTNISGROUP`;
  }

    `cat $GROUP >> $ADMENTNISGROUP`;
    `cat $PASSWD >> $ADMENTNISPASSWD`;
    $FPASSWD = $ADMENTNISPASSWD;

  }

  if ($PROCESSLDAP)                 
  {
    $FPASSWD = $LDAPPASSWD;
  }
  
  if($PROCESSNIS ==0 && $PROCESSLDAP == 0)
  {
    $FPASSWD = $PASSWD;
  }

  if ( $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0 && $OULD ==0 )
  {
    if ($IS_ADMIN_ENT_ACC == 1 &&( $OSNAME =~ /linux/i || $OSNAME =~ /sunos/i || $OSNAME =~ /solaris/i ))
    {
      `getent passwd > $ADMENTPASSWD`;
      $FPASSWD = $ADMENTPASSWD;
    }
    if ($IS_ADMIN_ENT_ACC == 2)
    {
      if( $VPREFIX eq "" )
      {
        `/opt/quest/bin/vastool list users-allowed > $ADMENTPASSWD`;
      }
      else
      {
        `/opt/quest/bin/vastool list users-allowed | sed \'s/$VPREFIX//g\' > $ADMENTPASSWD`;
      }
      logDebug("parsepw: vastool exitcode $?");
      `cat $PASSWD >> $ADMENTPASSWD`;
      $FPASSWD = $ADMENTPASSWD;
    }
    if ($IS_ADMIN_ENT_ACC == 3)
    {
      `adquery user > $ADMENTPASSWD`;
      `cat $PASSWD >> $ADMENTPASSWD`;
      logDebug("parsepw:  Centrify exitcode $?");
      $FPASSWD = $ADMENTPASSWD;
    }
  }

  logDebug("Processing $FPASSWD for users");
  open PASSWD_FILE, $FPASSWD || logAbort("Can't open $FPASSWD : $!");
  while (<PASSWD_FILE>)
  {
    $done_spasswd = 1;
    $domainname_user="";
    chomp;
    # parse passwd file
    ($username, $passwd, $uid, $gid, $gecos, $home, $shell) = split(/:/);
    logDebug("Before excluding domain name from user:$username");
    if($username =~ /(.+)\\(.+)/) {
	$domainname_user=$1;
        $username =$2;
        logDebug("After excluding domain name from user:$username and domain: $domainname_user");
    }
    if($domainname_user ne "") {
    	$Domain_user{$username}=$domainname_user;
    	logDebug("Domain name:$Domain_user{$username}");
    }
    logDebug("parsepw: read $username:$passwd:$uid:$gid:$gecos:$home:$shell");

    # store bits of user details in hashes
    # comment any we dont need to save memory !
    #$user_passwd{$username} = $passwd;
    #$user_uid{$username} = $uid;
    # only save priv groups
    
    if($username eq "")
    {
      logDebug("parsepw:Skip empty user name");      
      next;  
    }

    if($PROCESSNIS == 1 && $IS_NISPLUS == 1)
    {
      `groups $username >/dev/null 2>&1`;
      if( $? != 0 )
      {
        logDebug("parsepw:Skip NIS+ user");
        next;
      }
    }
    
    if($username =~ /^\+/)                                #V4.5
    {
      if ($LDAP == 0) {
        logInfo("User $username is excluded from output file, use --ldap option to lookup Netuser/Netgrp IDs");
        next;
      }
      if ($username =~ /^\+\@/) {
        logInfo("parsepw:Processing netgrp ID $username");
        Parse_LDAP_Netgrp($username);
        next;
      }
      ($username)= $username =~ /^\+(\S+)/;
      logInfo("parsepw:Processing netuser IDS $username");
      if(exists $user_gid{$username})
      {
        logDebug("parsepw:User $username already exist");
        next;
      }
      else
      {
        Parse_LDAP_Netusr($username);
      }
    }
    parse_user_info();

  } # end while
  close PASSWD_FILE;
  `rm -f $ADMENTPASSWD`;
  if ( $done_spasswd == 1 )
  {
    $state_available = 1;
  }
} # end sub parse

sub get_state_info()
{
  if ($OSNAME =~ /aix|vio/i)
  {
    &parsespw_aix();
  }
  elsif ($OSNAME =~ /hpux/i || $OSNAME =~ /hp-ux/i)
  {
    &parsespw_hpux();
  }
  else
  {
    &parsespw($OSNAME);
  }
}
sub auto_detect_vintela 
{
	my $runCmd = "/opt/quest/bin/vastool info servers";
	my $exit_code=system($runCmd);

	if($exit_code==0)
	{
  		$IS_ADMIN_ENT_ACC=2;
  		logInfo("Vintela is enabled in $OSNAME");
	} else {
		
  		logInfo("Vintela is disabled in $OSNAME");
	}
}

sub auto_detect_nis
{
         $FILE_NIS="/etc/nsswitch.conf";
         if ( -e $FILE_NIS ) {
                logInfo ("nsswitch.conf(NIS) found in $OS, Proceeding further...");
                $NisDetect=`cat $FILE_NIS | grep -v "^#" | grep "^passwd" | egrep -i "nis|nisplus"`;
		open FH_NIS, $FILE_NIS || logMsg(WARN,"Can't open $FILE_NIS : $!");
		while($line=<FH_NIS>) {
                        logDebug ("Reading nsswitch.conf file:$line");
		}
                if($NisDetect ne "") {
                        logInfo ("NIS is enabled with $OS");
                        $NIS=1;
                        $NOAUTOLDAP=1;
                } else {
                        logInfo ("NIS is disabled with $OS");
                        $NIS=0;
                        $NOAUTOLDAP=0;
               } 
        } else {
                logInfo ("nsswitch.conf does not exist in $OS, cannot fetch NIS information!");
        }
}

sub auto_detect_centrify
{
        $CENT_TMP="/tmp/cent.tmp";
        $FILE_CENT="/etc/nsswitch.conf";
  	if($OSNAME =~/AIX/) {
                $attr=`lssrc -s centrify-sshd > $CENT_TMP`;
		if ( $? != 0 )
                {
                        logDebug ("Checking other centrify service");
                        $attr=`lssrc -s centrifydc > $CENT_TMP`;
                }

		open FH_CENT, $CENT_TMP || logMsg(WARN,"Can't open $CENT_TMP : $!");
		while ($line=<FH_CENT>) {
			chomp($line);
                        logDebug ("Reading command output from AIX:$line");
                        $VAR=`echo $line | grep centrify | awk '{print \$NF}' | tr '[A-Z]' '[a-z]'`;
                        if ($VAR =~ /active/i) { 
                                $IS_ADMIN_ENT_ACC=3;
                                logInfo ("Centrify found with ACTIVE state, So Cetrify Enabled in server");
                        } elsif ($VAR =~ /inoperative/i) {
                                logInfo ("Centrify is installed but is INOPERATIVE, SO Centrify Disabled in server");
                        } else {
                                logInfo ("Centrify is not installed, So Centrify Disabled in server");
                        }

        	}
	}

  	if($OSNAME =~/Linux/) {
                $FILE_CENT="/etc/nsswitch.conf";
                if (-e $FILE_CENT) {
                        logInfo ("nsswitch.conf file found in $OS, Proceeding further...");
                        $CentrifyDetect=`cat $FILE_CENT | grep -v "^#" | grep "^passwd" | egrep -wi "centrify|centrifydc"`;
			while ($line=<FILE_CENT>) {
                                logDebug ("Reading nsswitch.conf file:$line");
			}
                        if ($CentrifyDetect ne "") {
                                logInfo ("Centrify is enabled with $OSNAME");
                                $IS_ADMIN_ENT_ACC=3;
                        } else {
                                logInfo ("Centrify is disabled with $OSNAME");
                        }
                        logInfo ("nsswitch.conf does not exist in $OSNAME, cannot fetch NIS information!");
                }
        }
			
}
sub get_vintela_state()
{
  if( $IS_ADMIN_ENT_ACC == 2 && $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0 )
  {
  logDebug("get_vintela_state: start");
  while ( (my $username, my $usergid) = each %user_gid)
  {
    if($local_users{$username} eq 1)#skip local user
    {
      logDebug("get_vintela_state: $username is a local user, skipped");
      next;
    }
    logDebug("username before check:$username");
    if($username =~ /\\(.+)/) {
        $username =$1;
    }

    logDebug("username after check:$username");

    my $attr=`/opt/quest/bin/vastool -u host/ attrs $username userAccountControl`;
    ($attr)=$attr =~ /(\d+)/;
    logDebug("get_vintela_state: LDAP user $username, attr is $attr");
    my $tmp=$attr & 2;
      if( $tmp == 0  && $attr != ""  )
    {
      $user_state{$username} = "Enabled";
      logDebug("get_vintela_state: $username is Enabled");
    }
    else 
    {
      $user_state{$username}="Disabled";
      logDebug("get_vintela_state: $username is Disabled");
    }  
  }  
  logDebug("get_vintela_state: end");    
 }
}

sub get_centrify_state()
{
  my $CENTRIFY_TMP="/tmp/centrify.tmp";
  
  if( $IS_ADMIN_ENT_ACC == 3 && $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0 )
  {
    logDebug("get_centrify_state: start");
    my $attr=`adquery user --unixname --disabled  > $CENTRIFY_TMP`;
    
    open CENTRIFY_FILE, $CENTRIFY_TMP || logMsg(WARN,"Can't open $CENTRIFY_TMP : $!\nWARN:  Account state may be missing from extract");
    while (<CENTRIFY_FILE>)
    {
      ($username, $field1, $field2) = split(/:/);
      
      logDebug("get_centrify_state: read line - $username, $field1, $field2");
      
      if( $field1 =~ /unixname/ )
      {
        next;
      }
      
      if( $field2 =~ /false/ )
      {
        $user_state{$username} = "Enabled";
        if($OSNAME =~ /AIX/i) 
        {
          $AIX_passwd_state{$username} = "Enabled";
          $AIX_user_state{$username} = "Enabled";
        }
        logDebug("get_centrify_state: $username is Enabled");
      }
      else 
      {
        $user_state{$username}="Disabled";
        if($OSNAME =~ /AIX/i)
        {
          $AIX_passwd_state{$username} = "Disabled";
          $AIX_user_state{$username} = "Disabled";
        }
        logDebug("get_centrify_state: $username is Disabled");
      } 
    }  
    `rm -f CENTRIFY_TMP`;
    logDebug("get_centrify_state: end");    
 }
}
#V9.7.0 added
#function to detect presence of ipa software of rhel idm for rbac
#Command=ipactl status
sub auto_detect_rhel_idm_ipa_rbac {

    logDebug("---auto_detect_rhel_idm_ipa_rbac: start---");
    logDebug("Initially RHELIDMIPA= $RHELIDMIPA");

    $RHELIDMIPA_TMP="/tmp/rhelidmipa.tmp";
    my $runCmd = "ipactl status > $RHELIDMIPA_TMP 2>&1";
    logDebug("Command=$runCmd");
    my $exit_code=system($runCmd);

    if($exit_code==0)
    {
        logDebug("Command ipactl status Executed: exit_code=$exit_code");
        logDebug("Processing File $RHELIDMIPA_TMP for ipactl command was successful");

        my $success_found=0;
        open RHELIDMIPA_TMP_FILE, $RHELIDMIPA_TMP || logAbort("Can't open $RHELIDMIPA_TMP : $!");
        while (my $Line = <RHELIDMIPA_TMP_FILE>)
        {
                chomp($Line);
                logDebug("line:   $Line");
                if($success_found==0)
                {
                        if($Line =~ /ipa: INFO: The ipactl command was successful/) {
                                logInfo("rhel Idm-Ipa for rbac is Detected - Installed");
                                $success_found=1;
                                $RHELIDMIPA=1;
                        }
                }
        }
        close RHELIDMIPA_TMP_FILE;
        `rm -f $RHELIDMIPA_TMP` ;

        if($success_found==0) {
                logInfo("rhel Idm-Ipa for rbac is Detected But Not Successful- Not Running");
        }
    } else {
        logInfo("Command ipactl status Failed: exit_code=$exit_code=");
                logInfo("rhel Idm-Ipa for rbac is Not Detected - Not Installed, Not Exists");
    }

    logDebug("Finally RHELIDMIPA= $RHELIDMIPA");
    logDebug("---auto_detect_rhel_idm_ipa_rbac: end---");

}

#V9.7.0 added
#function to process each user for the found rhel idm ipa environment 
#to get list of direct roles, indirect role:correponding group for each user
sub process_user_rhel_idm_ipa_rbac {

  my $username = shift;
  my $usr_all_domRoles = shift;
  my $is_idmUsr=0;

  logDebug("---process_user_rhel_idm_ipa_rbac start---");

  logDebug("Calling check_user_rhel_idm_ipa_rbac,,  user=$username, is_idmUsr=$is_idmUsr");
  $is_idmUsr=check_user_rhel_idm_ipa_rbac($username, $is_idmUsr);
  logDebug("Returned check_user_rhel_idm_ipa_rbac,, is_idmUsr=$is_idmUsr");

  if ( $is_idmUsr == 1 ) {
        logDebug("Calling check_userRole_rhel_idm_ipa_rbac,, user=$username");
        check_userRole_rhel_idm_ipa_rbac($username)
  }

  my ($usr_direct_domRoles, $usr_indirect_domRoles) = "";
  $usr_direct_domRoles   = join(',', @{$idm_ipa_UserRoles{$username}{'directRoles'}});
  $usr_indirect_domRoles = join(',', @{$idm_ipa_UserRoles{$username}{'indirectRoles'}});
  #usr_all_domRoles = usr_direct_domRoles + usr_indirect_domRoles
  if($usr_direct_domRoles ne "") {
        $usr_all_domRoles = $usr_direct_domRoles;
  }     
  if($usr_indirect_domRoles ne "") {
        if($usr_all_domRoles ne "") {
                $usr_all_domRoles = $usr_all_domRoles . ',' . $usr_indirect_domRoles;
        } else {
                $usr_all_domRoles = $usr_indirect_domRoles;
        }       
  }
   
  logDebug("Returning usr_all_domRoles = '$usr_all_domRoles'");
  
  logDebug("---process_user_rhel_idm_ipa_rbac end---");
  return $usr_all_domRoles;
  
}

#V9.7.0 added
#function to cross check user is from the ipa software of rhel idm for rbac
#Command=ipa user-find <username>

sub check_user_rhel_idm_ipa_rbac
{

  my $username = shift;
  my $is_idmUsr = shift;

  logDebug("---check_user_rhel_idm_ipa_rbac: start---");
  logDebug("Received username=$username, is_idmUsr=$is_idmUsr");

  $RHELIDMIPA_TMP="/tmp/rhelidmipa1.tmp";
  my $runCmd = "ipa user-find $username > $RHELIDMIPA_TMP 2>&1";
  logDebug("Command=$runCmd");
  my $exit_code=system($runCmd);

  logDebug("Command Output=");
  open RHELIDMIPA_TMP_FILE, $RHELIDMIPA_TMP || logAbort("Can't open $RHELIDMIPA_TMP : $!");
  while (my $Line = <RHELIDMIPA_TMP_FILE>)
  {
        chomp($Line);
        logDebug("line:   $Line");
  }
  close RHELIDMIPA_TMP_FILE;
  `rm -f $RHELIDMIPA_TMP` ;

  if($exit_code==0)
  {
        logDebug("Command ipa user-find Executed Successful : exit_code=$exit_code");
        logInfo("user $username is In Idm-Ipa, will process further..");
        $is_idmUsr=1;
  } else {
        logDebug("Command ipa user-find Executed : exit_code=$exit_code");
        logInfo("user $username is Not in Idm-Ipa, further process not required..");
        $is_idmUsr=0;
  }
logDebug("Returning   is_idmUsr=$is_idmUsr");
  logDebug("---check_user_rhel_idm_ipa_rbac: end---");
  return $is_idmUsr;
  
}

#V9.7.0 added
#function to find the group bringing the indirect role
sub parse_group_bringing_role 
{

  my ($indiRol, @idm_memberGroups) = @_;
  my $count = @idm_memberGroups;
  my $roleGrp="";

  logDebug("---parse_group_bringing_role: start---");
  logDebug("Received Indirect Role='$indiRol', idm_memberGroups= $count Groups='@idm_memberGroups'");

  OUTER:
  for (my $i = 0; $i < $count; $i++) {
        logDebug("Parsing Group $i='$idm_memberGroups[$i]'");
        my $idmGrp = $idm_memberGroups[$i];

        $RHELIDMIPA_TMP="/tmp/rhelidmipa3.tmp";
        my $runCmd = "ipa group-show $idmGrp > $RHELIDMIPA_TMP 2>&1";
        logDebug("Command=$runCmd");
        my $exit_code=system($runCmd);

        if($exit_code==0)
        {
                logDebug("Command group-show Executed Successful : exit_code=$exit_code");
        } else {
                logDebug("Command group-show Executed not Successful : exit_code=$exit_code");
                logAbort("Error in command execution, cross check command execution manually");
                return;
        }
	logDebug("Command Output=");
        open RHELIDMIPA_TMP_FILE, $RHELIDMIPA_TMP || logAbort("Can't open $RHELIDMIPA_TMP : $!");
        while (my $Line = <RHELIDMIPA_TMP_FILE>)
        {
                chomp($Line);
                logDebug("line:   $Line");

                if($Line =~ /Roles:/) {
                        logDebug("d. Group '$idmGrp' has Membership of ROLEs");

                        @idmGrp_memberRoles = split(':', $Line);
		#$idmGrp_memberRoles[0]=Roles  $idm_directRoles[1]= role1, role2,  ...
		@idmGrp_memberRoles = split(',', $idmGrp_memberRoles[1]);
		#$idmGrp_memberRoles[0]= role1   $idmGrp_memberRoles[1]= role2  ...
		$count_idmGrpRoles = @idmGrp_memberRoles;

                        logDebug("GROUP ROLEs = $count_idmGrpRoles ROLE(s) =@idmGrp_memberRoles");

                        for (my $i = 0; $i < $count_idmGrpRoles; $i++) {
                                logDebug("Parsing for Match: Group's Role $i='$idmGrp_memberRoles[$i]' V/S Indirect Role='$indiRol'");

                                my $idmGrpRol = $idmGrp_memberRoles[$i];
                                $idmGrpRol =~ s/^\s+|\s+$// ;
                                $idmGrp_memberRoles[$i] = $idmGrpRol;

                                if( $idmGrpRol eq $indiRol ) {
                                        logDebug("Matched, Group bringing Role '$indiRol' is '$idmGrp'");
                                        $roleGrp="$idmGrp";
                                        last OUTER;
                                } else {
                                        logDebug("Not Matched, Group bringing Role '$indiRol' is Not '$idmGrp'");
                                }
                        }
                }
        }
        close RHELIDMIPA_TMP_FILE;
        `rm -f $RHELIDMIPA_TMP` ;

  } #outer for ends here

logDebug("---parse_group_bringing_role: end---");

  if( $roleGrp eq "" ) {
        logDebug("Group NOT Found for bringing Role '$indiRol'='$roleGrp'");
        logAbort("Found erroneous data: no group matched for said role");
        return;
  } else {
        logDebug("Returning Group='$roleGrp' for the Role='$indiRol'");
        return $roleGrp;
  }

}

#V9.7.0 added
#function to check if the rhel idm user is Member/ accessor of any rbac Role
#user can be a role accessor either:
#a)directly as user b)indirectly through group c)none role
#Command=ipa user-show <username>

sub check_userRole_rhel_idm_ipa_rbac
{
  my $username = shift;

  logDebug("---check_userRole_rhel_idm_ipa_rbac: start---");
  logDebug("Received username='$username'");

  $RHELIDMIPA_TMP="/tmp/rhelidmipa2.tmp";
  my $runCmd = "ipa user-show $username > $RHELIDMIPA_TMP 2>&1";
  logDebug("Command=$runCmd");
  my $exit_code=system($runCmd);

  if($exit_code==0)
  {
        logDebug("Command ipa user-show Executed Successful : exit_code=$exit_code");
  } else {
        logDebug("Command ipa user-show Executed not Successful : exit_code=$exit_code");
        logAbort("Error in command execution, cross check command execution manually");
        return;
  }

  logDebug("Command Output=");
  open RHELIDMIPA_TMP_FILE, $RHELIDMIPA_TMP || logAbort("Can't open $RHELIDMIPA_TMP : $!");
  while (my $Line = <RHELIDMIPA_TMP_FILE>)
  {
chomp($Line);
    	logDebug("line:   $Line");

	if($Line =~ /Member of groups:/) {
  		logDebug("a. User $username has Membership of GROUPs");

                #my @idm_memberGroups = split(':', $Line);
                @idm_memberGroups = split(':', $Line);
                #$idm_memberGroups[0]=Member of groups $idm_memerGroups[1]= group1, group2,..
                @idm_memberGroups = split(',', $idm_memberGroups[1]);

                $count_memberGroups = @idm_memberGroups;
                logDebug("MEMBER GROUPs = $count_memberGroups GROUP(s) =@idm_memberGroups");

                for (my $i = 0; $i < $count_memberGroups; $i++) {
                        my $idmGrp = $idm_memberGroups[$i];
                        $idmGrp =~ s/^\s+|\s+$// ;
                        $idm_memberGroups[$i] = $idmGrp;
		}

	} elsif($Line =~ /Roles:/) {
  		logDebug("b. User $username has DIRECT Membership of ROLEs");

      		my @idm_directRoles = split(':', $Line);
		#$idm_directRoles[0]=Roles    $idm_directRoles[1]= role1, role2,  ...
      		@idm_directRoles = split(',', $idm_directRoles[1]);
		#$idm_directRoles[0]= role1   $idm_directRoles[1]= role2  ...

		my $count_directRoles = @idm_directRoles;
  		logDebug("DIRECT ROLEs = $count_directRoles ROLE(s) =@idm_directRoles");

		for (my $i = 0; $i < $count_directRoles; $i++) {
			my $diRol = $idm_directRoles[$i];
			$diRol =~ s/^\s+|\s+$// ;
			$idm_directRoles[$i] = $diRol;

			#Store in hash array of direct roles: 
			#username{'directRoles'} => [role1,role2,..]
                	push(@{$idm_ipa_UserRoles{$username}{'directRoles'}},$idm_directRoles[$i]);

                	logDebug("Stored Direct Role: {idm_ipa_UserRoles{$username}{'directRoles'}}[$i] ='${$idm_ipa_UserRoles{$username}{'directRoles'}}[$i]'");
		}

  		logInfo("Total DIRECT ROLEs STORED='@{$idm_ipa_UserRoles{$username}{'directRoles'}}'");

	} elsif($Line =~ /Indirect Member of role:/) {
  		logDebug("c. User $username has INDIRECT Member of ROLEs");

                my @idm_indirectRoles = split(':', $Line);
                #$idm_indirectRoles[0]=Indirect Member of role $idm_indirectRoles[1]= role1, role2,..
                @idm_indirectRoles = split(',', $idm_indirectRoles[1]);
                #$idm_indirectRoles[0]= role1   $idm_indirectRoles[1]= role2..
                
                my $count_indirectRoles = @idm_indirectRoles;
                logDebug("INDIRECT ROLEs = $count_indirectRoles ROLE(s) =@idm_indirectRoles");

                for (my $i = 0; $i < $count_indirectRoles; $i++) {
                        my $indiRol = $idm_indirectRoles[$i];
                        $indiRol =~ s/^\s+|\s+$// ;
                        $idm_indirectRoles[$i] = $indiRol;

                	logDebug("Finding Group bringing this Indirect Role $i='$idm_indirectRoles[$i]'");
			my $idmGrpRol = parse_group_bringing_role($idm_indirectRoles[$i], @idm_memberGroups);
                	logDebug("Received Group='$idmGrpRol'");

			#$idm_indirectRoles[$i] = "$idm_indirectRoles[$i]:$idmGrpRol"; 
			$idm_indirectRoles[$i] = "$idm_indirectRoles[$i]:%LDAP/$idmGrpRol"; #Added LDAP/ prefix

			#Store in hash array of indirect roles: 
			#username{'indirectRoles'} => [<rolename1>:<groupnameA>, ... ]
                	push(@{$idm_ipa_UserRoles{$username}{'indirectRoles'}},$idm_indirectRoles[$i]);
                	logDebug("Stored Indirect Role: {idm_ipa_UserRoles{$username}{'indirectRoles'}}[$i] ='${$idm_ipa_UserRoles{$username}{'indirectRoles'}}[$i]'");
                }

  			logInfo("Total INDIRECT ROLEs STORED='@{$idm_ipa_UserRoles{$username}{'indirectRoles'}}'");

	}
  }
  close RHELIDMIPA_TMP_FILE;
  `rm -f $RHELIDMIPA_TMP` ;
  logDebug("---check_userRole_rhel_idm_ipa_rbac: end---");

}

sub parsespw()
{
  my $FSPASSWD=$SPASSWD;
  
  if ( $IS_ADMIN_ENT_ACC == 1 && $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0 && $OULD ==0 )
  {
    if ($USERSPASSWD == 0 && ( $OSNAME =~ /linux/i ))
    {
      logDebug("parsespw: getent shadow");
      `getent shadow > $ADMENTSPASSWD`;
      $FSPASSWD = $ADMENTSPASSWD;
    }
  }

  open SPASSWD_FILE, $FSPASSWD || logMsg(WARN,"Can't open SPASSWD:$FSPASSWD : $!\nWARN:  Account state may be missing from extract");
  while (<SPASSWD_FILE>)
  {
    # set flag so we know what we've done
    $done_spasswd = 1;
    # parse shadow passwd file
    ($username, $crypt_passwd, $passwd_changed, $passwd_minage, $passwd_maxage, $passwd_war_period, $passwd_inactivity_period, $account_expiration, $reserved) = split(/:/);
      my $tmp;
      $PWNeverExpires_Arr{$username}="FALSE";
      if($passwd_changed eq "0")
      {
	$PWChg_Arr{$username}="";
        
      }
      else
      {
        if($passwd_changed eq "")
        {
          $PWNeverExpires_Arr{$username}="TRUE";
          $PWExp_Arr{$username}="31 Dec 9999";
        }
        else
        { 
          $PWChg_Arr{$username}=POSIX::strftime("%Y%m%d", localtime($passwd_changed * SEC_PER_DAY));
          if( $passwd_maxage ne "")
          {
            if($passwd_inactivity_period eq "" || $passwd_inactivity_period eq "99999")
            {
              $passwd_inactivity_period=0;
            }

            $tmp=$passwd_changed + $passwd_maxage + $passwd_inactivity_period;
            $tmp=POSIX::strftime("%d %b %Y", localtime($tmp * SEC_PER_DAY));
            $PWExp_Arr{$username}=$tmp;
          }
          else
          {
            $PWExp_Arr{$username}="";
          }
        }
      }
      $PWMinAge_Arr{$username}=$passwd_minage;
      $PWMaxAge_Arr{$username}=$passwd_maxage;
      if($passwd_maxage eq "99999" || $passwd_maxage eq "")
      {
        $PWNeverExpires_Arr{$username}="TRUE";
        $PWExp_Arr{$username}="31 Dec 9999";
      }
    
    # check for user disabled by NP, *LK*, !!, or * in password field
    if ( ($crypt_passwd =~ /\*LK\*/) or ($crypt_passwd =~ /^!/) or ($crypt_passwd =~ /^\*/))
    {
      $user_state{$username} = "Disabled";
      $scm_user_state{$username} = "1";
      logDebug("$username Disabled: crypt=$crypt_passwd in shadow");
    }
    if ( $crypt_passwd eq "LOCKED")
    {
      $user_state{$username} = "Disabled";
      $scm_user_state{$username} = "1";
      logDebug("$username Disabled: crypt=$crypt_passwd in shadow");
    }
    
    if (($user_state{$username} eq "Disabled") and ($PUBKEYAUTH eq "yes"))
    {
      logDebug("Checking for public key file $home/$AUTHORIZEDKEYSFILE for user: $username");
      $home=$user_home{$username};
      if (( -e "$home/$AUTHORIZEDKEYSFILE" ) || ( -e "$home/$AUTHORIZEDKEYSFILE2" ))
      {
        $user_state{$username} = "SSH-Enabled";
        logDebug("SSH key file is found:$username");
      }
    }
    
    
  } # end while
  close SPASSWD_FILE;
  `rm -f $ADMENTSPASSWD`;

  # if we have processed the file set state_available flag
  if ( $done_spasswd == 1 )
  {
    $state_available = 1;
  }

} # end sub parse

sub hp_logins
{
  my $username = shift;
  
  logDebug("hp_logins:start");
  
  my ($F1,$F2,$F3,$F4,$F5,$F6,$F7,$F8,$F9,$F10,$F11,$F12,$F13,$F14) = split(/:/, `logins -axo -l $username`);
  
  if(($F11 eq "-1" && $F10 eq "-1") || $F9 eq "000000" || $F9 eq "")
  {
    $PWNeverExpires_Arr{$username}="TRUE";
  }
  else
  {
    $PWNeverExpires_Arr{$username}="FALSE";
  }
  
  if($F11 eq "-1")
  {
    $F11="99999";
  }

  if($F10 eq "-1")
  {
    $F10="0";
  }
  
  $PWMaxAge_Arr{$username}=$F11;
  $PWMinAge_Arr{$username}=$F10;
  
  if($F11 ne "99999" && $F9 ne "000000")
  {
    my $MM=substr("$F9",0,2);
    my $DD=substr("$F9",2,2);
    my $YY="1970";
    if($F9 ne "010170")
    {
      $YY=substr("$F9",4,2);
    }
    my $change=timelocal(0, 0, 0, $DD, $MM-1, $YY);
    $PWExp_Arr{$username}=POSIX::strftime("%d %b %Y", localtime($change+$F11*SEC_PER_DAY));
  }
  else
  {
    $PWExp_Arr{$username}="31 Dec 9999";
  }  
  
  if( $F9 eq "000000" || $F9 eq "" || $F9 eq "010170")
  {
    $F9="01 Jan 1970";
  }
  else
  {
    my $MM=substr("$F9",0,2);
    my $DD=substr("$F9",2,2);
    my $YY=substr("$F9",4,2);
    $F9=formatDate($MM, $DD, $YY);
  }
  $PWChg_Arr{$username}=$F9;
}

sub parsespw_hpux()
{
  # check to see if command is executable
  # if getprpw is found, we assume this is a TCB machine
    open PASSWD_FILE, $PASSWD || logAbort("Can't open $PASSWD : $!");
    while (<PASSWD_FILE>)
    {
      # set flag so we know what we've done
      $done_getprpw = 1;
      # parse passwd file
      ($username, $crypt_passwd, @rest) = split(/:/);
      
      logDebug("parsespw_hpux: username $username, crypt_passwd $crypt_passwd");
      if($MEF4FORMAT)      
      {
        hp_logins($username);
      }
      
      if(-x "/usr/lbin/getprpw" && -d "/tcb")
      {
        $getprpwdcmd="/usr/lbin/getprpw -m lockout $username|";
        #$getprpwdcmd="echo \"lockout=0010000\"|";
        open GETPRPW, $getprpwdcmd || logMsg(WARN, "Can't open $getprpwdcmd : $!\nAccount state may be missing from extract");
        $hpstatus=<GETPRPW>;
        chomp $hpstatus;
        # set flag so we know what we've done
        if($hpstatus =~ /1/)
        {
          $user_state{$username} = "Disabled";
          $scm_user_state{$username} = "1";
          logDebug("parsespw_hpux: $username Disabled hpstatus=$hpstatus returned from getprpw");
        }
        else
        {
          logDebug("parsespw_hpux: $username  hpstatus=$hpstatus");
        }
        close GETPRPW;
      }
      else
      {
        open PP, "passwd -s $username 2>&1 |";
        while (<PP>)
        {
          logDebug("parsespw_hpux: $_"); 
          if( $_ =~ /LK/)
          {
            $user_state{$username} = "Disabled";
            $scm_user_state{$username} = "1";
            last;
          }
        }  
        close PP;      
      }

      if(defined($user_state{$username}) && $user_state{$username} eq "Disabled")
      {
        if ( $PUBKEYAUTH eq "yes" )
        {
          $home=$user_home{$username};
          if (( -e "$home/$AUTHORIZEDKEYSFILE" ) || ( -e "$home/$AUTHORIZEDKEYSFILE2" ) )
          {
            $user_state{$username} = "SSH-Enabled";
          }
        }
      } 
    }# end while
    close PASSWD_FILE;
    $state_available = 1;
} # end sub parse

sub store_aix_data
{
  if($username ne "")
  {
    my $maxage=$PWMaxAge_Arr{$username};
    my $maxexpired=$PWMaxExpired_Arr{$username};
    if( $maxage eq "0" || $maxexpired eq "-1")
    {
     $PWNeverExpires_Arr{$username}="TRUE";
     $PWExp_Arr{$username}="31 Dec 9999";
     $PWMaxAge_Arr{$username}="99999";
    }
    else
    {
      $PWNeverExpires_Arr{$username}="FALSE";
      my $LastUpdate=$PWLastUpdate{$username};
      if($LastUpdate ne "")
      {
        $PWExp_Arr{$username}=POSIX::strftime("%d %b %Y", localtime($LastUpdate + $maxage*SEC_PER_DAY + $maxexpired*7*SEC_PER_DAY));
      }
      else
      {
        $PWExp_Arr{$username}="";
      }
   }
 }    
}

sub parsespw_aix()
{
  my $tmp=0;
    
  # Now do user security/user file
  open SUSER_FILE, $SUSER || logMsg(WARN,"Can't open SECUSER:$SUSER : $!\nAccount state may be missing from extract");
  while (<SUSER_FILE>)
  {
    if(/^\*/)
    {
      next;
    }
    # set flag so we know what we've done
    $done_suser = 1;
    # parse security user file
    # Find the usernamne
    if (/(.+):/)
    {
      # $1 is the bit matched by (.+)
      $username = $1;
      logDebug("parsespw_aix: found user $username");
      if($MEF4FORMAT)
      {
        store_aix_data();
        if($username ne "default")
        {
          $PWMinAge_Arr{$username}=$PWMinAge_Arr{"default"};
          $PWMaxAge_Arr{$username}=$PWMaxAge_Arr{"default"};
          $PWExp_Arr{$username}=$PWExp_Arr{"default"};
          $PWMinLen_Arr{$username}=$PWMinLen_Arr{"default"};
          $PWNeverExpires_Arr{$username}=$PWNeverExpires_Arr{"default"};
          $PWMaxExpired_Arr{$username}=$PWMaxExpired_Arr{"default"};
        }
      } 
      next;
    }
    # Find the password
    if (/account_locked = (.+)/)
    {
      # $1 is the bit matched by (.+)
      # check for user disabled by true in account_locked field
      $account_locked = $1;
      if ($account_locked =~ /true|yes|always/i )
      {
        $AIX_user_state{$username} = "Disabled";
        $scm_user_state{$username} = "1";
        logDebug("parsespw_aix: $username Disabled: account_locked=$account_locked in security user");
      }
      else
      {
        $AIX_user_state{$username} = "Enabled";
        $scm_user_state{$username} = "1";
        logDebug("parsespw_aix: $username Enabled: account_locked=$account_locked in security user");
      }
      next;
    }

    if($MEF4FORMAT)    
    {
      if (/minage = (.+)/)
      {
        $tmp=$1*7;
        $PWMinAge_Arr{$username}=$tmp;
        next;
      }
      
      if (/maxage = (.+)/)
      {
        $tmp=$1*7;
        $PWMaxAge_Arr{$username}=$tmp;
        next;
      }
      
      if (/minlen = (.+)/)
      {
        $PWMinLen_Arr{$username}=$1;
        next;
      }
      
      if (/maxexpired = (.+)/)
      {
        $PWMaxExpired_Arr{$username}=$1;
        next;
      }
    }

  } # end while

  close SUSER_FILE;

  if($MEF4FORMAT)
  {
    store_aix_data();
  }
  
  $username="";
  # Do security/passwd file
  open SPASSWD_FILE, $SPASSWD || logMsg(WARN, "Can't open SPASSWD:$SPASSWD : $!\nAccount state may be missing from extract");
  while (<SPASSWD_FILE>)
  {
    # set flag so we know what we've done
    $done_spasswd = 1;
    # parse security passwd file
    # Find the usernane
    my $nextline = trim($_);
    if ( $nextline =~ /(.+):/)
    {
      # $1 is the bit matched by (.+)
      $username = $1;
      next;
    }
    # Find the password
    if ( $nextline =~ /password\s*=\s*(.+)/)
    {
      # $1 is the bit matched by (.+)
      # check for user disabled by * in password field
      $crypt_passwd = $1;
      if ($crypt_passwd =~ /^\*/ )
      {
        $AIX_passwd_state{$username} = "Disabled";
        $scm_user_state{$username} = "1";
        logDebug("$username Disabled: password=$crypt_passwd in security passwd");
      }
      else
      {
        $AIX_passwd_state{$username} = "Enabled";
        $scm_user_state{$username} = "0";
        logDebug("$username Enabled: password=$crypt_passwd in security passwd");
      }
    next;
  }

    if ( $nextline =~ /lastupdate = (.+)/)
    {
      $PWChg_Arr{$username}=POSIX::strftime("%Y%m%d", localtime($1));
      $PWLastUpdate{$username}=$1;
    }
  }

  close SPASSWD_FILE;

  # if we have processed both files set state_available flag
  if ( $done_spasswd == 1 and $done_suser == 1 )
  {
    $state_available = 1;
  }
} # end sub parse

sub parsegp()
{
  if ($PROCESSNIS)                  # V 4.5
  {
    if ($IS_NISPLUS)
   {
    `niscat passwd.org_dir$NISPLUSDIR > $ADMENTNISPASSWD`;
    `niscat group.org_dir > $ADMENTNISGROUP`;
  }
  else
  {
    `ypcat passwd > $ADMENTNISPASSWD`;
    `ypcat group > $ADMENTNISGROUP`;
  }

    `cat $GROUP >> $ADMENTNISGROUP`;
    `cat $PASSWD >> $ADMENTNISPASSWD`;
    $FPASSWD = $ADMENTNISPASSWD;
    $FGROUP = $ADMENTNISGROUP;
  }

  if ($PROCESSLDAP)                 
  {
    $FPASSWD = $LDAPPASSWD;
    $FGROUP = $LDAPGROUP;
  }
  
  if($PROCESSNIS ==0 && $PROCESSLDAP == 0)  
  {
    $FPASSWD = $PASSWD;
    $FGROUP = $GROUP;
  }

  if ( $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0 && $OULD ==0)
  {
    if ($IS_ADMIN_ENT_ACC == 1 && ( $OSNAME =~ /linux/i  || $OSNAME =~ /sunos/i || $OSNAME =~ /solaris/i) )
    {
      logDebug("parsegp: getent");
      `getent passwd > $ADMENTPASSWD`;
      `getent group > $ADMENTGROUP`;

      $FPASSWD = $ADMENTPASSWD;
      $FGROUP  = $ADMENTGROUP;
    }
    
    if ($IS_ADMIN_ENT_ACC == 2 ) 
    {
      logDebug("parsegp: vastool");
      if( $VPREFIX eq "" )
      {
        `/opt/quest/bin/vastool list users-allowed > $ADMENTPASSWD`;
        `/opt/quest/bin/vastool list -a groups > $ADMENTGROUP`;
      }
      else
      {
        `/opt/quest/bin/vastool list users-allowed | sed \'s/$VPREFIX//g\' > $ADMENTPASSWD`;
        `/opt/quest/bin/vastool list -a groups | sed \'s/$VPREFIX//g\' > $ADMENTGROUP`;
      }
      `cat $GROUP >> $ADMENTGROUP`;
      $FPASSWD = $ADMENTPASSWD;
      $FGROUP  = $ADMENTGROUP;
    }
    
    if ($IS_ADMIN_ENT_ACC == 3 ) 
    {
      logDebug("parsegp:  Centrify");
      `adquery user > $ADMENTPASSWD`;
      `adquery group > $ADMENTGROUP`;
      `cat $GROUP >> $ADMENTGROUP`;
      $FPASSWD = $ADMENTPASSWD;
      $FGROUP  = $ADMENTGROUP;
    } 
  }
  
  logDebug("Processing $FGROUP for privileges groups");
#$ggid{ibmunixadm}="730";
  open GROUP_FILE, $FGROUP || logAbort("Can't open $FGROUP : $!");
  while (<GROUP_FILE>)
  {
   $domainname_group="";
    # parse group file
    ($groupname, $passwd, $gid, $userlist) = split(/:/);
    chomp $userlist;
    chomp $groupname;
    logDebug("parsegp: read $groupname:$passwd:$gid:$userlist");    
    if($groupname eq "")
    {
      logDebug("Skip empty group name");      
      next;  
    }

    if($groupname =~ /^\+/)
    {
      logDebug("Skip group $groupname");
      next;
    }
    if($groupname =~ /(.+)\\(.+)/) {
      $domainname_group=$1;
      $groupname =$2;
      logDebug("After excluding domain name from the group: $groupname,domain group: $domainname_group");
    }
 
    if($domainname_group ne "") {
    logDebug("domain name for group $groupname is $domainname_group");
    $Domain_group{$groupname}=$domainname_group;
   	
   }
    
    # store group-gid info in hash
    $group{$gid} = $groupname;
    $ggid{$groupname} = $gid;

    %gmemlist=();
    $allusers=$primaryGroupUsers{$gid}; 
    foreach $username (split(/\,/,$userlist))
    {
      if ( !defined $gmembers{$gid})
      {
        $gmembers{$gid} = $username;
      }
      else
      {
      # add user only user not in current list
      foreach $nlist (split(/\,/,$gmembers{$gid}))
      {
        $gmemlist{$nlist}=$nlist;
      }
      if($gmemlist{$username})
      {
        ## already in list
      }
      else
      {
        $gmembers{$gid} = $gmembers{$gid}.",$username";
      }
    }
  }

  #$gmembers{$gid} = $userlist;

  if($primaryGroupUsers{$gid})
  {
    if($userlist eq "")
    {
      $allusers=$primaryGroupUsers{$gid};
    }
    else
    {
      $allusers="$primaryGroupUsers{$gid},$userlist";
    }
  }
  else
  {
    $allusers="$userlist";
  }

    logDebug("parsegp: userlist: $userlist");
    logDebug("parsegp: allusers: $allusers");
    #uniquify the privgrouplist
    if($allusers ne "")
    {
      %hash=();
      @cases = split(/,/,$allusers);
      $allusers = "";
      %hash = map { $_ => 1 } @cases;
      $allusers = join(",", sort keys %hash);
    }
    logDebug("parsegp: UNIQUE allusers: $allusers");
    #uniquify the privgrouplist

    $FOUNDPG=is_priv_group($groupname, $gid);
  
    # store priv user groups info in hash
    foreach $username (split(/,/,$allusers))
    {
      if (exists $user_allgroups{$username})
      {
        my $is_founded_dublicate = 0;
        foreach my $usergroup (split(/,/,$user_allgroups{$username}))
        {
          if ($usergroup eq $groupname)
          {
            $is_founded_dublicate = 1;
          }
        }

        if (!$is_founded_dublicate)
        {
          $user_allgroups{$username} = $user_allgroups{$username} . "," . $groupname;
        }
      }
      else
      {
        $user_allgroups{$username} = $groupname;
      } # end if

    if ($FOUNDPG)
    # only save priv groups
    {
      logDebug("ADDING priv group $groupname, ID $username");
      if (exists $user_privgroups{$username})
      {
        my $is_founded_dublicate = 0;
        foreach my $userprivgroup (split(/,/,$user_privgroups{$username}))
        {
          if ($userprivgroup eq $groupname)
          {
            $is_founded_dublicate = 1;
          }
        }
        if (!$is_founded_dublicate)
        {
          $user_privgroups{$username} = $user_privgroups{$username} . "," . $groupname;
        }
      }
      else
      {
        $user_privgroups{$username} = $groupname;
      } # end if
    } # end if
  } # end foreach
} # end while
close GROUP_FILE;
`rm -f $ADMENTPASSWD`;
`rm -f $ADMENTGROUP`;
} # end sub parse

sub parsesudoers()
{
  my $tmp_sudo_file="/tmp/sudoersfile.tmp";
  `rm -f $tmp_sudo_file`;
  
  &preparsesudoers($SUDOERS, $tmp_sudo_file);
  
  $SUDOALL="2";
  open SUDOERS_FILE, $tmp_sudo_file || logMsg(WARN, "Can't open SUDOERS:$tmp_sudo_file : $!\nAccount SUDO privileges will be missing from extract");
  while ($nextline = <SUDOERS_FILE>)
  {
    chomp($nextline);
    logDebug("SUDOERS:read $nextline");
    chomp $nextline;
    ## concatenate line with next line if line ends with \
    if ( $nextline =~ /\\\s*$/ )
    {
      # process continuation line
      ($nline)=$nextline=~/(.*)\\\s*$/;
      chomp($nline);
      chop($nextline);
      $InputLine .= $nline;
      next;
    }
    $InputLine .= $nextline;

    ## trim out comment lines
    $cmt_ix = index( $InputLine, "#" );
    if ( $cmt_ix >= 0 )
    {
      $InputLine = substr( $InputLine, 0, $cmt_ix);
    }

    # split line into tokens (names and keywords)
    @Line = split /[,=\s]/, $InputLine;
    $ix = 0;

    # classify pieces of the input
    TOKEN: while ( $ix <= $#Line ) {
      if ( $Line[$ix] eq "" ) {  # ignore seperators
        $ix++;
        next TOKEN;
      }
      if ( $Line[$ix] eq "Cmnd_Alias" ){
        last TOKEN;
      }
      if ( $Line[$ix] eq "Runas_Alias" ){
        last TOKEN;
      }
      if ( $Line[$ix] eq "Defaults" ){
        last TOKEN;
      }
      if ( $Line[$ix] eq "ALL" ){     # v.7.3 ignore SUDOALL if ALL=!SUDOSUDO rule found *** start *****
        if ($InputLine =~ /!/ || $InputLine =~ /noexec/i ) {
          $SUDOALL="0";
          logInfo("Found ALL=!Cmnd_Alias :$InputLine");
        }
        else {
          if($SUDOALL eq "2") {
            if($InputLine =~ /ALL\s+(\S+)\s*=/)
            {
              if( defined $validHostAlias{$1} || $1 =~/ALL/)
              {
                logInfo("Found ALL :$InputLine");
                $SUDOALL="1";
              }
            }
            else
            {
              logInfo("Found ALL :$InputLine");
              $SUDOALL="1";
            }
          }
        }               # v.7.3 ignore SUDOALL if ALL=!SUDOSUDO rule found **** end *****
        last TOKEN;
      }

      if ( $Line[$ix] eq "Host_Alias" ){
        ($hostalias,$hostlist)=$InputLine=~/\s*\w+\s+(\w+)\s*\=\s*(.+)/;
        $hostlist =~ s/\s//g;
        logDebug("SUDOERS: $InputLine");
        logDebug("SUDOERS: Found Host_Alias $hostalias");
        logDebug("SUDOERS: Found hostlist $hostlist");

        foreach $nextHost (split ',', $hostlist)
        {
	  $nextHost =~ s/\[//;
          $nextHost =~ s/\]//;
          $nextHost=lc glob2pat($nextHost);
          if ( $HOST =~ /$nextHost/i || $LONG_HOST_NAME =~ /$nextHost/i || "ALL" =~ /$nextHost/i)
          {
            $validHostAlias{$hostalias}=$hostalias;
            logDebug("SUDOERS: Found VALID Host_Alias $hostalias");
          }
        }
        last TOKEN;
      }
      if ( $Line[$ix] eq "User_Alias" ){  # extract user names
        # User_Alias USERALIAS = user-list
        ($useralias,$aliaslist)=$InputLine=~/\s*\w+\s+(\w+)\s*\=\s*(.+)/;
        $aliaslist =~ s/\s//g;
        # record useralias name so that it is not confused with a user name
        logDebug("SUDOERS: $InputLine");
        logDebug("SUDOERS: Found user_alias $useralias=$aliaslist");
        $AliasList{$useralias} = $aliaslist;
	 foreach $usr (split ',', $aliaslist)
        {
          if($UserAliasList{$usr})
          {
            $UserAliasList{$usr}.=",$useralias";
          }
          else
          {
            $UserAliasList{$usr}.="$useralias";
          }

          if ( exists $AliasList{$usr} )#is it an aliasname
          {
            logDebug("SUDOERS:Alias of Alias $useralias:$usr");

            if($AliasOfAlias{$useralias})
            {
              $AliasOfAlias{$useralias}.=",$usr";
            }
            else
            {
              $AliasOfAlias{$useralias}.="$usr";
            }
          }
        }
        last TOKEN;
      }  # end if User_Alias

      # this line must be in "user access_group" format
      # e.g. root ALL = (ALL) ALL
      # e.g. root host = (ALL) ALL
      # e.g. root Host_Alias = (ALL) ALL
      # e.g. %grop ALL = (ALL) ALL
      ($userlist,$hostlist)=$InputLine=~/\s*([\w\,\%\+\@\/\s\-:]+\w)\s+([\,\!\w\s]+)\s*\=/;
      $userlist =~ s/\s//g;
      $hostlist =~ s/\s//g;
	if($userlist eq "" && $hostlist eq "") {	
		if($InputLine=~/^\s*(%.+?)\s+([\,\!\w\s]+)\s*\=/) {
			logDebug("groups found in sudoers file:$InputLine");	
  			$userlist=$1;
   			$hostlist=$2;
   		}
	}

      logDebug("SUDOERS: $InputLine");
      logDebug("SUDOERS: Found userlist $userlist");
      logDebug("SUDOERS: Found hostlist $hostlist");
      $PROCESSLINE=0;
      foreach $nextHost (split ',', $hostlist)
      {
        my $nextHost1=lc glob2pat($nextHost);

        if ( $HOST =~ /$nextHost1/i || $LONG_HOST_NAME =~ /$nextHost1/i)
        {
          logDebug("SUDOERS: PROCESSLINE=1, $nextHost = $HOST");
          $PROCESSLINE=1;
          last;
        }
        elsif ("ALL" =~ /$nextHost1/i)
        {
          logDebug("SUDOERS: PROCESSLINE=1, $nextHost = ALL");
          $PROCESSLINE=1;
          last;
        }
        elsif ($validHostAlias{$nextHost})
        {
          logDebug("SUDOERS: PROCESSLINE=1, $nextHost ValidHostALias");
          $PROCESSLINE=1;
          last;
        }
      }
      
      if ($PROCESSLINE)
      {
        if ($LDAP == 1 )
        {             #V7.5
          if ($userlist =~ /^\@\w+/ ) {
            ($userlist) = $userlist =~ /^\@(\S+)/;
            $userlist = $netgrouplist{$userlist};
            logDebug("Found Netgrp $userlist");
          }
          elsif ( $userlist =~ /^\+\w+/ ){
            ($userlist) = $userlist =~ /^\+(\S+)/;
            $userlist = $userlist;
            logDebug("Found Netusr $userlist");
          }
        }
        }
      foreach $next (split ',', $userlist)
      {
        logDebug("SUDOERS: add name $next");
        $User_List{$next}=$PROCESSLINE;
       }
       
      last TOKEN;
    }  # end TOKEN: while ix
    $InputLine= "";
  } # end while

  close SUDOERS_FILE;

  while(($key, $value) = each %User_List)
  {
    if($value == 1 )
    {
      add_name($key);
    }
  };
  
  if($SUDOALL eq "2") {
    $SUDOALL="0";
  }
  `rm -f $tmp_sudo_file`;
} # end sub parse

sub ProcessUserAlias
{
  my $useralias = $_[0];


  logDebug("ProcessserAlias: User_Alias: $useralias");
  my $aliaslst=$AliasList{$useralias};
  logDebug("ProcessserAlias: aliaslist: $aliaslst");
  
  foreach $nxt (split ',', $aliaslst)
  {
    # processing groups listed in User Alias
    if( $nxt =~ s/^%:*//)
    {
      if ($ggid{$nxt} eq "")
      {
        logMsg(WARN, "invalid group $nxt in $SUDOERS User_Alias");
      }
      else
      {
        my $Members;
        my $NewName;
        logDebug("ProcessUserAlias: Found group $nxt in User_Alias");
        # Swapped out function calls with access of the prepopulated associative arrays
        $Members = $gmembers{$ggid{$nxt}};
        foreach $NewName (split ',', $Members)
        {
          logDebug("ProcessUserAlias: Found user $NewName in group $nxt in User_Alias $useralias");
          make_alias_of_alias($NewName, $useralias, $nxt);
        }
      }
  }
  elsif ( $nxt ne "" )
  {
    if(exists $user_gid{$nxt})
    {
      logDebug("ProcessUserAlias: Add alias to user $nxt $useralias");
      make_alias_of_alias($nxt, $useralias, "");
    }
    else
    {
      if(exists $AliasList{$nxt})
      {
        ProcessSubAlias($useralias,$nxt);            
      }
      else
      {
        logMsg(WARN, "Invalid user $nxt in $SUDOERS $useralias");
      }
    }
  }  # if Line
 }  # end while each in useralias
} # end sub processuseralias

### Subroutine add_name - add name to list
#
# Call:
#   add_name(name)
#
# Arguments:
#   name - name to add to username alias list
#          ( %name if group name )
#
# User_Alias names are ignored.
# Group names are expanded to include all of the group members.
sub add_name
{
  my $Aname = $_[0];
  logDebug("add_name: Processing $Aname");

  if ( exists($AliasList{ $Aname }))
  {
    # ignore User_Alias names
    logDebug("SUDOERS: Found user alias $Aname");
    ProcessUserAlias($Aname);
    return 0;
  }
  # process user ids and group names
  if ( $Aname =~ /^%/ )
  {
    # trim leading "%:" to get group name
    $Aname =~ s/^%:*//;
    # get list of user ids
  my $key_Aname = 0; 
  while(($k,$v)=each(%ggid)) {
      if($k =~ /$Aname/i) {
	    $Aname=$k;
	    $key_Aname =1;
      } 
  }

   #$key_Aname = grep { /^$Aname$/i } keys %ggid; 
   if ($key_Aname == 0 && ($KERB != 1 || $OULD != 1)) {

       logMsg(WARN, "invalid group $Aname in $SUDOERS");
       return 1;
   }

   # if ($ggid{$Aname} eq "")
   # {
     # logMsg(WARN, "invalid group $Aname in $SUDOERS");
     # return 1;
   # }

    my $Members;
    my $NewName;
    logDebug("SUDOERS: Found group $Aname");
    # Swapped out function calls with access of the prepopulated associative arrays
     if ($KERBFlag ==1 ) {
        logDebug("SUDOERS: Sudoers grp: $Aname,Kerb group $KGrp, user $Kuid");
        if (grep { $_ eq $Aname } @Kgroups)  {
                logDebug("SUDOERS: sudoers group and Kerb group are same");
                $KerbGroupPriv{$Aname}="privgroup";
        }
    }
	if ($OULD ==1 ) {
        #logDebug("SUDOERS: Sudoers grp: $Aname,Kerb group $KGrp, user $Kuid");
        if (grep { $_ eq $Aname } @AllLGroups)  {
                logDebug("SUDOERS: sudoers group: $Aname and ould group:$_ are same");
                $OULDGroupPriv{$Aname}="privgroup";
        }
    }
	
    $Members = $gmembers{$ggid{$Aname}};
    foreach $NewName (split ',', $Members)
    {
      # add each user id
      # NO check to see if ID is in EXEMPT list of users?!
      ## only add to hash if user is added alone, not as part of group
      ##########  $UserList{ $NewName }++;
      if ($UserGroup{$NewName})
      {
        $UserGroup{$NewName}.=",$Aname";
      }
      else
      {
        $UserGroup{$NewName}.="$Aname";
      }
    }
  }
  else
  {
  # add a simple user id
    $UserList{ $Aname }++;
    logDebug("SUDOERS: Found user $Aname");
  }  # end if/else group name
  return 0;
}  # end subroutine add_name

sub openout()
{
  # Split out the path and filename portions
  my($filename, $directories, $suffix) = fileparse($OUTFILE);

  # path must exist
  if ( ! -e $directories )
  {
    logAbort("Output directory $directories does not exist");
  }

  # Resolve OUTFILE dirname to deferrence any symlinks
  # need to be absolutely sure what we are writing to !
  my $abs_path = abs_path($directories);

  # refuse to proceed if it looks like a system path
  # eg /usr /etc /proc /opt
  if ( $abs_path =~ /^\/usr/ or $abs_path =~ /^\/etc/ or $abs_path =~ /^\/proc/ or $abs_path =~ /^\/opt/)
  {
    logAbort("Output directory $abs_path not allowed");
  }

  # refuse to proceed output file exists and is not a plain file
  if ( -e $OUTFILE and ! -f $OUTFILE )
  {
    logAbort("Won't remove $OUTFILE not a normal file");
  }

  # and refuse if it is a symlink
  if ( -l $OUTFILE )
  {
    logAbort("Won't remove $OUTFILE is a symlink");
  }

  # If it exists and is a standard file remove it
  if ( -e $OUTFILE and -f $OUTFILE )
  {
    `rm -f $OUTFILE` ;
    if ($? != 0)
    {
      logAbort("Can't remove old $OUTFILE : $?");
    }
  }

  # Open the output file for writing
  open OUTPUT_FILE, ">$OUTFILE" || logAbort("Can't open $OUTFILE for writing : $!");
} # end sub openout

sub remove_labeling_delimiter
{
    my $labellingData = shift;    
    $labellingData =~ s/\|/ /g;    
    return $labellingData;
}

sub get_urt_format{
    my $_usergecos = shift;
    
    my $_LCgecos=lc($_usergecos); 
    my $_userurt = 0;
    my $_userstatus = "";
    my $_usercust = "";
    my $_usercomment = "";
    my $_userserial = "";
    my $_userCCC = "";
    my $_userCC = "";
    
    logDebug("get_urt_format input: $_usergecos");
    if($_usergecos =~ /IBM|Kyndryl\s+\S{6,6}\s+\S{3,3}($|\s)/)
    {
        $_userstatus="K";
        $_usercust="";
        $_usercomment=$_usergecos;
        ($_userserial, $_userCCC)= $_usergecos=~/IBM|Kyndryl\s+(\S{6,6})\s+(\S{3,3})/;
        $_userCC=$_userCCC; 
    }
    elsif ($_usergecos =~ /\w{2,3}\/\w{1}\// )
    {
        $_userurt = 1;
    }
    elsif ($_LCgecos =~/s\=\S{9,9}/)
    {
        $_userstatus="K";
        $_usercust="";
        $_usercomment=$_usergecos;
        
        ($_userserial,$_userCCC)=$_LCgecos=~/s\=(\S{6,6})(\S{3,3})/;
        $_userCC=$_userCCC; 
    }
    else
    {
        $_userstatus="C";
        $_usercust="";
        $_usercomment=$_usergecos;
        $_userCC=$USERCC;
        $_userserial=""; 
    }
    
    my $_userinfo = "";
    
    if ($_userurt) {                                                                                                                             #7.4 Updated code to check URT format CCC/I/ in gecos field
        $_userinfo = "$_usergecos";
    }
    else {
        $_userinfo = "$_userCC/$_userstatus/$_userserial/$_usercust/$_usercomment";
    }
    logDebug("get_urt_format output: $_userinfo");    
    return remove_labeling_delimiter($_userinfo);
}

sub check_lpwchg_date_format
{
	my $lpwchg=shift;
	my $YY=substr("$lpwchg",0,4);
        my $MM=substr("$lpwchg",4,2);
        my $DD=substr("$lpwchg",6);	
	if($DD =~ /\b\d\b/) {
    
                $DD ="0"."$DD";
        }
	my$FinalFormat="$YY$MM$DD";
	return $FinalFormat;
}

sub get_last_logon_user_id
{
  my $loginname=shift;
  my $str       = '';
  my $lastlogon = '';
  
  logDebug("retrieving last logon for user '$loginname' (OS - $OSNAME)");
  
  for ($OSNAME)
  {
      my %monthnames = ('Jan', '01', 'Feb', '02', 'Mar', '03', 'Apr', '04', 'May', '05', 'Jun', '06', 'Jul', '07', 'Aug', '08', 'Sep', '09', 'Oct', '10', 'Nov', '11', 'Dec', '12' );

      if(/linux/i)
      {
          $str = `lastlog -u $loginname 2>/dev/null`;
          $str=trim($str);
          if($str =~ /^$loginname[\s]*[^\s]*[\s]*[^\s]*[\s]*(\w+)[\s]+(\w+)[\s]+(\d+)[\s]+(\d+:\d+:\d+)[\s]+([^\s]*)[\s]+(\d+)/m)
          {
              $lastlogon = "$3 $2 $6";
              $lastlogon = "$6$monthnames{$2}$3";
          }
      }
		
      elsif(/aix/i)
      {
          $str = `lsuser -f $loginname 2>/dev/null`;
          $str=trim($str);
          logDebug("'$str'");
          if($str =~ /^[\s]*time_last_login=(\d+)/m)
          {
              $lastlogon = POSIX::strftime("%Y%m%d", localtime($1));
          }
      }
	  elsif(/vio/i)
      {
          $str = `last $loginname | head -1 2>/dev/null`;
          $str=trim($str);
		  $currentYear = `date +%Y`;
		  $currentYear=trim($currentYear);
		  logDebug(" last command out:$str");
          if($str =~ /^$loginname[\s]*[^\s]*[\s]*[^\s]*[\s]*(\w+)[\s]+(\d+)[\s]+(\d+:\d+)[\s]+.*/m)
          {
              $lastlogon = "$2 $1 $currentYear";
          }
      }
      else{

          logDebug("User name before fqdn check: $loginname");
          $loginname=`echo $loginname | sed 's/@/\\@/'`;
          logDebug("User name after fqdn check: $loginname");

          if($loginname =~ /^([a-z0-9.-_]+)\@[a-z0-9.-]+$/) {
                $loginname = $1;
                logDebug("shortname: $loginname");
          }

          $str = `finger -hfp $loginname 2>/dev/null`;
          $str=trim($str);
          logDebug("'$str'");

          my @buffer = split(/\n/, $str);
          my $currentYear = `date +%Y`;
          $currentYear=trim($currentYear);
          my $currentMonth = `date +%m`; chomp($currentMonth);
          %mnames = ('Jul', 1, 'Aug', 2, 'Sep', 3, 'Oct', 4,
                  'Nov', 5, 'Dec', 6, 'Jan', 7, 'Feb', 8, 'Mar', 9,
                  'Apr', 10, 'May', 11, 'Jun', 12 );

          foreach (@buffer)
          {
            if ($_ =~ /On since\s+(\w+)\s+(\d+)\s+\d+:\d+/)
            {
            # current month before July and logon month before Jan
               --$currentYear if ($mnames{$currentMonth} > 6 && $mnames{$1} < 7);
                my $day = $2;
                my $year =$currentYear;
                my $mon =$1;
                if($day =~ /^\d$/) {
                        $day = "0$day";
                }
               $lastlogon = "$year$monthnames{$mon}$day";

              last;
             }
             elsif($_ =~ /Last login\s+\w+\s+(\w+)\s+(\d+)\s+\d+:\d+/)
             {
              --$currentYear if ($mnames{$currentMonth} > 6 && $mnames{$1} < 7);
                my $day = $2;
                my $year =$currentYear;
                my $mon =$1;
                if($day =~ /^\d$/) {
                        $day = "0$day";
                }

               $lastlogon = "$year$monthnames{$mon}$day";

               last;
             }
             elsif($_ =~ /Last login\s+\w+\s+(\w+)\s+(\d+),\s+(\d+).*/)
             {
                $lastlogon = "$2 $1 $3";
                           my $day = $2;
                           my $year =$3;
                           my $mon =$1;
                           if($day =~ /^\d$/) {
                                   $day = "0$day";
                                }
               $lastlogon = "$year$monthnames{$mon}$day";

               last;
             }                 
           }
       }
  }
  logDebug("lastlogon = '$lastlogon'");
  chomp($lastlogon); 
  return $lastlogon;
}


sub get_last_logon_user_id_new_format
{
  my $loginname=shift;
  my $str       = '';
  my $lastlogon = '';
  my $currentYear = `date +%Y`; chomp($currentYear);
  $currentYear=trim($currentYear);
  my $currentMonth;
  my $currentDay = `date +%d`; chomp($currentDay);
  logDebug("retrieving last logon for user '$loginname' (OS - $OSNAME)");
  
  for ($OSNAME)
  {
           my %monthnames = ('Jan', '01', 'Feb', '02', 'Mar', '03', 'Apr', '04', 'May', '05', 'Jun', '06', 'Jul', '07', 'Aug', '08', 'Sep', '09', 'Oct', '10', 'Nov', '11', 'Dec', '12' );
		   my %mnames = ('Jul', '01', 'Aug', '02', 'Sep', '03', 'Oct', '04',
                  'Nov', '05', 'Dec', '06', 'Jan', '07', 'Feb', '08', 'Mar', '09',
                  'Apr', '10', 'May', '11', 'Jun', '12' );
      if(/linux/i)
      {		 
		  $ENV{'LANG'} = 'en_US.UTF-8';
          $str = `lastlog -u $loginname 2>/dev/null`;
          $str=trim($str);
		  logDebug("retrieving last logon linux: each line: $str");
          if($str =~ /^$loginname[\s]*[^\s]*[\s]*[^\s]*[\s]*(\w+)[\s]+(\w+)[\s]+(\d+)[\s]+(\d+:\d+:\d+)[\s]+([^\s]*)[\s]+(\d+)/m)
          {
	      $yyyy = $6; 
          $mm = $2;
		  $mm = ucfirst($mm);
	      $dd = $3;
	      if($dd =~ /\b\d\b/) {

		$dd ="0"."$dd";	
	      }
              $lastlogon = "$yyyy$monthnames{$mm}$dd";

          }
      }
	  
      elsif(/aix/i)
      {
          $str = `lsuser -f $loginname 2>/dev/null`;
          $str=trim($str);
          logDebug("'$str'");
          if($str =~ /^[\s]*time_last_login=(\d+)/m)
          {
              $lastlogon = POSIX::strftime("%Y%m%d", localtime($1));
          }
      }
	  	  elsif(/vio/i)
      {
          $str = `last $loginname | head -1 2>/dev/null`;
          $str=trim($str);
		  $currentMonth = `date +%b`; chomp($currentMonth);
		  logDebug(" last command out:$str");
          if($str =~ /^$loginname[\s]*[^\s]*[\s]*[^\s]*[\s]*(\w+)[\s]+(\d+)[\s]+(\d+:\d+)[\s]+.*/m)
          {
			  my ($mon, $day) = ($1, $2);
			  my $year = $currentYear;

			  # Convert to numeric for comparison
			  my $loginMonthNum = $monthnames{$mon};
			  my $currentMonthNum = $monthnames{$currentMonth};

			  # Remove leading 0s for numeric comparison
			  $loginMonthNum =~ s/^0//;
			  $currentMonthNum =~ s/^0//;
			  $day =~ s/^0//;
			  $currentDay =~ s/^0//;

			  # Decrement year if login is in future
			  if ($loginMonthNum > $currentMonthNum ||
				  ($loginMonthNum == $currentMonthNum && $day > $currentDay)) {
				  $year--;
			  }

			  # Re-pad day if needed
			  $day = sprintf("%02d", $day);

			  $lastlogon = "$year$monthnames{$mon}$day";
			  logDebug(" last logon date VIO:$lastlogon");
          }
      }
      else{
	  logDebug("User name before fqdn check: $loginname");
          $loginname=`echo $loginname | sed 's/@/\\@/'`;
          logDebug("User name after fqdn check: $loginname");

          if($loginname =~ /^([a-z0-9.-_]+)\@[a-z0-9.-]+$/) {
                $loginname = $1;
                logDebug("shortname: $loginname");
          }

          $str = `finger -hfp $loginname 2>/dev/null`;
          $str=trim($str);
          logDebug("'$str'");
          
          my @buffer = split(/\n/, $str);
          $currentMonth = `date +%m`; chomp($currentMonth);
          
          foreach (@buffer)
          {
            if ($_ =~ /On since\s+(\w+)\s+(\d+)\s+\d+:\d+/)
            {
            # current month before July and logon month before Jan
               --$currentYear if ($mnames{$currentMonth} > 6 && $mnames{$1} < 7);
                my $day = $2;
                my $year =$currentYear;
                my $mon =$1;
                if($day =~ /^\d$/) {
                        $day = "0$day";
                }
               $lastlogon = "$year$monthnames{$mon}$day";

              last;
             }
             elsif($_ =~ /Last login\s+\w+\s+(\w+)\s+(\d+)\s+\d+:\d+/)
             {
              --$currentYear if ($mnames{$currentMonth} > 6 && $mnames{$1} < 7);
                my $day = $2;
                my $year =$currentYear;
                my $mon =$1;
                if($day =~ /^\d$/) {
                        $day = "0$day";
                }

               $lastlogon = "$year$monthnames{$mon}$day";

               last;
             }
             elsif($_ =~ /Last login\s+\w+\s+(\w+)\s+(\d+),\s+(\d+).*/)
             {
                $lastlogon = "$2 $1 $3";
                           my $day = $2;
                           my $year =$3;
                           my $mon =$1;
                           if($day =~ /^\d$/) {
                                   $day = "0$day";
                                }
               $lastlogon = "$year$monthnames{$mon}$day";

               last;
             }                 
           }
       }
  }
  logDebug("lastlogon = '$lastlogon'");
  chomp($lastlogon); 
  return $lastlogon;
}
 
sub report_group()
{
  my $remote_group="FALSE";
  my $privilege="";
  if ($PROCESSLDAP || $PROCESSNIS) 
  {
    $remote_group="TRUE";
  }
  
  while ( (my $groupgid, my $groupname) = each %group)
  {
    if( $IS_ADMIN_ENT_ACC != 0 && $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0)
    {
      if(exists $local_groups{$groupname})
      {
        $remote_group="FALSE";
      }
      else
      {
        $remote_group="TRUE";
      }
    }    
    
    if($remote_group eq "FALSE")
    {
      if( exists $privgroups{$groupname})
      {
        $privilege="TRUE";
      }
      else
      {
        $privilege="FALSE";
      }
    }
    else
    {
      $privilege="";
    }
    
    print OUTPUT_FILE "G|$URTCUST|S|$HOSTNAME|$OSNAME|$groupname||$groupgid||$remote_group|$privilege\n";
  }
}

sub getTimeZone
{
    my $RAWTIMEZONE="";
    my $TIMEZONE="";
    my $sign="";
    my $hours="";
    my $minutes="";
    my $tz;

    # http://alma.ch/perl/perloses.htm
    if ( $OSNAME =~ /HPUX/i || $OSNAME =~ /HP-UX/i )
    {
        my $offset = "";

        my $time_zone_abbr;
        chomp($time_zone_abbr = `date +%Z`);
        return $offset if ($time_zone_abbr eq "");

        my $tztab_location = "/usr/lib/tztab";
        return $offset if (! -f $tztab_location);

        # need to get a list of lines that matches the time_zone_abbr
        my @offsets = ();

        open TZ_HANDLER, "$tztab_location" or do {
            warn "[WARN] Can't open file $tztab_location : $!\n";
            return $offset;
        };
        my $tz_var = $ENV{"TZ"};
        my $block = 0;

        while (<TZ_HANDLER>) {
            chomp;
            # remove comments
            s/#.*//;
            s/^\s*//;
            s/^\s*$//;
            # if tz_var exist
            if ($tz_var ne "") {
                # getting block
                if (/^$tz_var$/) {
                    $block = 1;
                    next;
                }
                next if ($block != 1);
                last if ($block == 1 && $_ eq "");
            }
            my @fields = split(/\s+/, $_);
            if (scalar(@fields) ge 7 && $fields[6] =~ /^$time_zone_abbr([0-9:-]+)$/) {
                push(@offsets, $1);
            }
        }
        while (@offsets) {
            # clear value
            $offset = "";
            my $last_value = pop @offsets;

            $sign = "-";
            $hours = "";
            $minutes = "";

            if ($last_value =~ /^(-?)(\d{1,2})(:(\d{1,2}))?(:.*)?$/) {

                $hours = defined $2 && $2 ne "" ? $2 : "0";
                $minutes = defined $4 && $4 ne "" ? sprintf("%0.2f", $4 / 60) : "0";
                $sign = "+" if ($1 eq "-" || $hours == 0 && $minutes == 0);
                $offset = $sign . ($hours + $minutes);
                last;
            }
        }
        close TZ_HANDLER;
        $TIMEZONE = $offset;
    }
    else
    {
        $RAWTIMEZONE=`date +%z`;
        if($OSNAME =~/aix/i)
        {
            $sign=substr($RAWTIMEZONE,3,1);
            $hours=substr($RAWTIMEZONE,4,2);
            $minutes=substr($RAWTIMEZONE,7,2);
        }
        else
        {
            $sign=substr($RAWTIMEZONE,0,1);
            $hours=substr($RAWTIMEZONE,1,2);
            $minutes=substr($RAWTIMEZONE,3,2);
        }
        #print "'$sign' ... '$hours' ... '$minutes'\n";
        if($sign ne '+' && $sign ne '-')
        {
            $sign = '';
        }
        else
        {    
            $tz = ($minutes > 0) ? $hours+$minutes/60 : $hours+0;
        }
        $TIMEZONE="$sign$tz";
    }
    return trim($TIMEZONE);
}

sub ProcessSubAlias
{
  my $parent_alias=shift;
  my $alias = shift;

  my $aliaslst=$AliasList{$alias};
  logDebug("ProcesssSubAlias: parent $parent_alias, alias $alias, aliaslist $aliaslst");
  
  foreach $nxt (split ',', $aliaslst)
  {
    # processing groups listed in User Alias
    if( $nxt =~ s/^%:*//)
    {
      if ($ggid{$nxt} ne "")
      {
        logDebug("ProcessSubAlias: Found group $next in $alias");
        my $Members = $gmembers{$ggid{$nxt}};
        foreach my $NewName (split ',', $Members)
        {
          logDebug("ProcessSubAlias: Found user $NewName in group $nxt in $alias");
          store_user_alias($NewName, "$parent_alias:%$nxt");
        }
      } 
    }
    elsif ( $nxt ne "" )
    {
      if(exists $user_gid{$nxt})
      {
        logDebug("ProcessSubAlias: Add alias to user $nxt $useralias");
        store_user_alias($nxt, "$parent_alias:$alias");
      }
      else
      {
        if(exists $AliasList{$nxt})
        {
          logDebug("ProcessSubAlias: Found subalias user $nxt, alias $nxt");
          ProcessSubAlias($parent_alias,$nxt);            
        }
      }
    }  
  }  
} 

my $found="";
sub find_last_alias
{
  my $alias=shift;
  my $subalias=$AliasOfAlias{$alias};
    
  logDebug("find_last_alias: alias '$alias' subalias '$subalias'");
  
  if($subalias ne "" && $found eq "")
  {
    foreach $tempAlias (split(/,/,$subalias))
    {
      if($found eq "")
      {
        $subalias=find_last_alias($tempAlias);
        logDebug("find_last_alias:alias $tempAlias, found subalias $subalias");
        if($subalias eq "")
        {
          $found=$alias;
          last; 
        }
      }
    }
  }
  else
  {
    $found=$alias;
  }
  logDebug("find_last_alias: return subalias $found");
  return $found;
}

sub make_alias_of_alias
{
  my $user=shift;
  my $alias=shift;
  my $group=shift;
  my $str="";
  
  logDebug("make_alias_of_alias: user $user, alias $alias, group $group");
  
  $found="";
  my $subalias=find_last_alias($alias);
  logDebug("make_alias_of_alias: user $user, alias $alias subalias $subalias");
  if($subalias eq $alias)
  {
    $subalias="";
  }
  
  if( $subalias ne "")
  {
    store_user_alias($user, "$alias:$subalias");
    my $aliasgroup=&make_alias_of_group($user, $subalias);
    if($aliasgroup ne "")
    {
      store_user_alias($user, "$alias:%$aliasgroup");
    }
  }
  if( $group ne "" )
  {
    store_user_alias($user, "$alias:%$group");
  }
  else
  {
    store_user_alias($user, $alias);
  }
}

sub make_alias_of_group
{
  my $user=shift;
  my $alias=shift;
  
  my $aliaslist=$AliasList{$alias};
  my $usergroups=$user_allgroups{$user};
  
  logDebug("make_alias_of_group: user $user, alias $alias, aliaslist $aliaslist, usergroups $usergroups");
  
  foreach $aliasgroup (split(/,/,$aliaslist))
  {
    if( $aliasgroup =~ s/^%:*//) # if group
    {
      foreach $usergroup (split(/,/,$usergroups))
      {
        if($usergroup eq $aliasgroup)
        {
          logDebug("make_alias_of_group: user $user, alias $alias, found usergroup $usergroup");
          return $usergroup;
        }
      }
    }
  }
  return "";
}

sub store_user_alias
{
  my $user=shift;
  my $valstr=shift;


  if($valstr eq "")
  {
    return;
  }
  my $str=$UserAlias{$user};
  
  if ($str =~ /$valstr(,+|$)/)
  {
    logDebug("store_user_alias: $valstr is found");
    return;
  }
  
  logDebug("store_user_alias: user $user, value $valstr, sudostr $str");
  if($str eq "")
  {
    $UserAlias{$user}="SUDO_ALIAS($valstr";
  }
  else
  {
    $UserAlias{$user}="$str,$valstr";
  }
}


sub add_domain_to_group_name 
{
  $privs_group=shift;
  @All_groups="";
  foreach $each_group (split(/,/,$privs_group)) {
        $groups_with_domain="";
        logDebug ("Processing each group to add domain name group:$each_group");
        if (exists $Domain_group{$each_group}) {
                logDebug ("group: $each_group has domain name: $Domain_group{$each_group}");
                $groups_with_domain="$Domain_group{$each_group}\\".$each_group;
                push(@All_groups,$groups_with_domain);
        } else {
		push(@All_groups,$each_group);
	}
  }
  if(scalar(@All_groups)) {
        $groups_with_domain =join(",",@All_groups);
        $groups_with_domain =~ s/^,//g;
        logDebug("Group feild after adding domain name:$groups_with_domain");
  }
  return $groups_with_domain;
}

sub report()
{
  #==============================================================================
  # Produce the urt extract file
  #==============================================================================
  # URT .scm format is ....
  # hostname<tab>os<tab>account<tab>userIDconv<tab>state<tab>l_logon<tab>group<tab>privilege
  #
  #print "INFO:  Writing report for customer: $URTCUST to file: $OUTFILE\n";

  my $UICmode="";
  my $UID="";
  my $PWMinLen="";
  my $PWChg="";
  my $PWMaxAge="";
  my $PWMinAge="";
  my $PWExp="";
  my $PWNeverExpires="FALSE";
  my $idm_ipa_UserRoles = ();     #V9.7.0 added 
  logInfo("Reporting...");
  
  if($MEF4FORMAT)
  {
    if($OSNAME =~ /linux/i)
    {
      $PWMinLen=getFromThere("/etc/pam.d/system-auth","^password\\s*requisite\\s*pam_cracklib.so.*minlen=(\\d+).*");
      if($PWMinLen eq "")
      {
        $PWMinLen=getFromThere("/etc/login.defs","^PASS_MIN_LEN\\s*(\\d+).*");
      }
      logDebug("report:PWMinLen=$PWMinLen");
    }elsif( $OSNAME =~ /sunos/i || $OSNAME =~ /solaris/i ) 
    {
      $PWMinLen=getFromThere("/etc/default/passwd","^PASSLENGTH=(\\d+)\$");
      logDebug("report:PWMinLen=$PWMinLen");
    }elsif( $OSNAME =~ /HPUX/i || $OSNAME =~ /HP-UX/i ) 
    {
      $PWMinLen=getFromThere("/etc/default/security","^MIN_PASSWORD_LENGTH=(\\d+)\$");
      if($PWMinLen eq "")
      {
        $PWMinLen="6";
      }
    }
  }
	my $OSVER1=`uname -v`;
	if($OSVER1 =~ /photon/i) {
		logInfo("PHOTON OS detected");
		$OSNAME="$OSNAME"."-"."PHOTON"
	}  
  while ( (my $username, my $usergid) = each %user_gid)
  {
    $usergecos=$userllogon=$groupField=$privField=$userstate="";
    $UICmode="";
    $UID="";
    $PWChg="";
    $PWMaxAge="99999";
    $PWMinAge="0";
    $PWExp="31 Dec 9999";
    $PWNeverExpires="FALSE";

    ## skip id if  it preceded by +:
    if($username =~ /^\+/)
    {
      logInfo("User $username is excluded from output file, use --ldap option");
      next;
    }

    # gather the info
    $usergecos = $user_gecos{$username};
    $usergecos=remove_labeling_delimiter($usergecos);
    
    # set userstate depending on what we were able to extract
    if ( $state_available == 1 )
    {
      logDebug("report: $username check user state");
      # we have extracted all disabled accounts - rest must be enabled
      #if $user_state{username}=have value  the user_state=value
      #else user_state="Enabled"
      if($OSNAME !~ /AIX|VIO/i) 
      {
        $userstate = $user_state{$username} ? $user_state{$username} : "Enabled";
        $scm_userstate = defined $scm_user_state{$username} ? $scm_user_state{$username} : "0";
        logDebug("report: user state for $username is $userstate.");
		
      }
      else
      {
        $acclocked=$AIX_user_state{"default"};
        if(defined $AIX_user_state{$username})
        {
          $acclocked=$AIX_user_state{$username};
        }
        logDebug("report: User $username, account $acclocked"); 
        if( $acclocked eq "Enabled")
        {
          if( defined $AIX_passwd_state{$username})
          {
            $userstate=$AIX_passwd_state{$username};
            logDebug("report: User $username, passwdstate $userstate");
          }
        }
        if($acclocked eq "Disabled" && $userstate eq "")
          {
            $userstate="Disabled";
          }
        if($acclocked eq "Enabled" && $userstate eq "")
          {
            $userstate="Enabled";
          }
        if( $acclocked eq "Enabled" && $userstate eq "Disabled")# && ($AIX_user_login{$username} eq "false" || $AIX_user_rlogin{$username} eq "false") )
        {
          if ( $PUBKEYAUTH eq "yes" )
          {
            $home=$user_home{$username};            
            if (( -e "$home/$AUTHORIZEDKEYSFILE" ) || ( -e "$home/$AUTHORIZEDKEYSFILE2" ) )
            {
              $userstate = "SSH-Enabled";
              logDebug("Report: Found SSH Key for $username, user is $userstate");
            }
          }
        }
		if($OSNAME =~ /VIO/i) {
			my $userstate_lsuser = `lsuser $username 2>/dev/null`;
			chomp($userstate_lsuser);
			logDebug("report: ls user state for $username is $userstate_lsuser.");
			if($userstate_lsuser =~ /^$username\s.*login=(\w+).*\srlogin=(\w+).*account_locked=(\w+)/m)
			{
				my $login=$1;
				my $rlogin=$2;
				my $acc_lock=$3;
				logDebug("report: login: $login ,rlogin = $rlogin,acc lock: $acc_lock.");
				if($acc_lock eq "true") {
					$userstate = "Disabled";
					logDebug("report if: ls user state for $username is $userstate.");
				} elsif($acc_lock eq "false") {
					if($login eq "false" && $rlogin eq "false") {
						$userstate = "Disabled";
						logDebug("report: ls user state for $username is $userstate.");
					} elsif($login eq "true" && $rlogin eq "true") {
						$userstate = "Enabled";
						logDebug("report elsif: ls user state for $username is $userstate.");
					} else {
                        $userstate = "Disabled";
                        print("report else: ls user state for $username is $userstate.");
                    }
				}
			}
		}
        logDebug("Report: User $username is $userstate");
      }
    }
    else
    {
      # we may have extracted some disabled accounts eg from passwd file but maybe not all
      # so default set blank
      $userstate = $user_state{$username} ? $user_state{$username} : "";
      $scm_userstate = $scm_user_state{$username} ne "" ? $scm_user_state{$username} : "0";
    }

  $gid=$user_gid{$username};
  $UID=$user_uid{$username};
  
  if ( ! exists $group{$gid})
  {
    logMsg(WARN,"user $username is in group $gid. Unable to resolve group $gid to a name");
    if($PROCESSNIS || $PROCESSLDAP)
    {
      logMsg(WARN,"skip user $username");
      next;
    }
  }
  
  if (exists $user_allgroups{$username})
  {
    $groupField=$user_allgroups{$username};
  }
  else
  {
    logMsg(WARN,"no any group found for user $username");
  }
  
  
  $privField="";

  if($user_privuser{$username})
  {
    logDebug "Found privileged ID: $username";
    $privField=$username;
  }

  if($OSNAME =~ /VIO/)
  {
    my $userroles = `lsuser -a roles $username 2>/dev/null`;
    chomp($userroles);
    logDebug("Report: User roles $userroles");
    logDebug("Report:roles1 $userroles");  
    ($userroles)=$userroles=~/=\s*(\S+)/;
    logDebug("Report:roles2 $userroles");
    
    foreach $role (split(/,/,$userroles))
    {    
      logDebug("Report:add user roles $role");
      my $role_name=$ROLE{$role};
      if($role_name eq "")
      {
        $role_name=$role;
      }
      else #privileged role
      {
        if($privField eq "")
        {
          $privField="ROLE($role_name)";
        }
        else
        {
          $privField=$privField.","."ROLE($role_name)";
        }
      }
        
      if($groupField eq "")
      {
        $groupField="ROLE($role_name)";
      }
      else
      {
        $groupField=$groupField.","."ROLE($role_name)";
      }
    }
  }
  
  if($user_privgroups{$username})
  {

    $group_privs=$user_privgroups{$username};
    logDebug("Prefixing domain name to GRP groups:$group_privs");
    $groupname_with_domain = add_domain_to_group_name($group_privs);
    logDebug("GRP groups after prefixing domain name:$groupname_with_domain");
    $groupValue="GRP($groupname_with_domain)";
    if ($PROCESSLDAP || $IS_ADMIN_ENT_ACC == 2 || $IS_ADMIN_ENT_ACC == 3) {

        my @Pgroups=();
        foreach $Pgroup (split(/,/,$groupname_with_domain)) {
                logDebug("Check LDAP group for privilige: $groupname_with_domain ");
                if($local_groups{$Pgroup} != 1) {
                        $groupname_with_domain = "LDAP/" . $Pgroup;
                        push(@Pgroups,$groupname_with_domain);
                        logDebug("Report group for privilige: $groupname_with_domain - Add LDAP group prefix");
                } else {
                        push(@Pgroups,$Pgroup);
		}
        }
        $groupname_with_domain = join(",", @Pgroups);
    	$groupValue="GRP($groupname_with_domain)";
    }


    if($privField eq "")
    {
      $privField=$groupValue;
    }
    else
    {
    	logDebug("Prv feild1:$privField, Sudo value:$SudoValue");
	$privField=$privField.",".$groupValue;
   }
  }	
  if ($SUDOALL eq "1")
  {
    if($privField eq "")
    {
      $privField="SUDO_ALL";
    }
    else
    {
      $privField=$privField.",SUDO_ALL";
    }
  }

  if ($UserGroup{$username})
  {
    $usersudogroups=$UserGroup{$username};
    logDebug("Report: userID $username, sudousergroup $usersudogroups");
    #uniquify the sudogrouplist
    %hash=();
    @cases = split(/,/,$usersudogroups);
    $usersudogroups = "";
    %hash = map { $_ => 1 } @cases;
    @All_privgroups="";
    $SudoGroup="";
    foreach $priv_group (sort keys %hash) {
	$privgroups_with_domain="";
	logDebug ("Processing privilige sudo groups to add domain name group:$priv_group");
        if (exists $Domain_group{$priv_group}) {
                logDebug ("priv group: $priv_group has domain name: $Domain_group{$priv_group}");
                $privgroups_with_domain="$Domain_group{$priv_group}\\".$priv_group;
                push(@All_privgroups,$privgroups_with_domain);
        } else {
                logDebug ("priv group: $priv_group does not has any domain name");
                push(@All_privgroups,$priv_group);
        }

    }
   if(scalar(@All_privgroups)) {  
        $usersudogroups = join(",",@All_privgroups);
        $usersudogroups =~ s/^\s*,//g;
	if($usersudogroups ne "") {
        	$SudoGroup="SUDO_GRP($usersudogroups)";
	}
    }
    if($privField eq "")
    {
      $privField=$SudoGroup;
    }
    else
    {
    	logDebug("Prv feild2:$privField, Sudo value:$SudoGroup");
	$privField=$privField.",".$SudoGroup;
    }
  }
  
  if($UserAlias{$username})
  {
    if($privField eq "")
    {
      $privField=$UserAlias{$username};
    }
    else
    {
    	logDebug("Prv feild3:$privField, Alias:$UserAlias{$username}");
        $privField=$privField.",$UserAlias{$username}";
    }
    $privField=$privField.")";
  }

  $SudoValue="";
  if ($UserList{$username})
  {
      if ( $IS_ADMIN_ENT_ACC != 0 && $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0)
      {
          if($local_users{$username} != 1)
          {
              $sudo_user = "SUDO_LDAP\/";
              logDebug("$username is priviliged sudo user, So adding SUDO_LDAP to prefix");
          } else {
              $sudo_user = "SUDO\_";
              logDebug("$username is priviliged user, So adding SUDO to prefix");
          }
      } else {

              $sudo_user = "SUDO\_";
              logDebug("else:$username is priviliged user, So adding SUDO to prefix");
      }

    if(exists $Domain_user{$username}) {
        $username="$Domain_user{$username}\\".$username;
        logDebug ("Adding domain name for SUDO user:$Domain_user{$username} to user: $username");
    }
    $SudoValue=$sudo_user.$username;

    if($privField eq "")
    {
      $privField=$SudoValue;
    }
    else
    {
      logDebug("Prv feild4:$privField, Sudo value:$SudoValue");
      $privField=$privField.",".$SudoValue;
    }
    delete $UserList{$username};
  }
  
    if(defined $PWChg_Arr{$username})
    {
      $PWChg=$PWChg_Arr{$username};
    }
  if($MEF4FORMAT)
  {
    my $tmpval="";
    
    if(defined $PWNeverExpires_Arr{$username})
    {
      $PWNeverExpires=$PWNeverExpires_Arr{$username};
    }
    
    if(defined $PWExp_Arr{$username})
    {
      $PWExp=$PWExp_Arr{$username};
    }
    
    $tmpval=$PWMaxAge_Arr{$username};
    if($tmpval ne "")
    {
      $PWMaxAge=$tmpval;
      if($OSNAME =~ /AIX/i && $tmpval eq "0")
      {
        $PWNeverExpires="TRUE";
        $PWExp="31 Dec 9999";
      }
    }
    
    if(defined $PWMinAge_Arr{$username})
    {
      $tmpval=$PWMinAge_Arr{$username};
      if($tmpval ne "")
      {
        $PWMinAge=$tmpval;
      }
    }
    
    if($OSNAME =~ /AIX/i)
    {
      $PWMinLen=$PWMinLen_Arr{$username};
    }
  }
 
 
  if(exists $Domain_user{$username}) {
	$username="$Domain_user{$username}\\".$username;			
	logDebug ("Adding domain name:$Domain_user{$username} to user: $username");
  }

    	logDebug("Prefixing domain name to groups:$groupField");
     	$groupField_with_domain = add_domain_to_group_name($groupField);
    	logDebug("Groups after prefixing domain name: $groupField_with_domain");
	$groupField=$groupField_with_domain;

  if ($PROCESSNIS)
  {
  	if($local_users{$username} != 1)
    	{
    		$username = "NIS/" . $username;
    		logDebug("Report: $username - Add NIS prefix");
    		if($Dormant eq "ON_ON") {
			$userllogon = "";	
			$PWChg ="";
    		} elsif($Dormant eq "ON_OFF") {
			$userllogon = "";
  		}
	}
   }

  if ($PROCESSLDAP)
  {
  
    #V9.7.0 added 
    if( $RHELIDMIPA == 1 )
    {
	my $usr_all_domRoles="";

      	logDebug("Calling Location A");
      	logDebug("Calling process_user_rhel_idm_ipa_rbac,,  user=$username, usr_all_domRoles='$usr_all_domRoles'");
    	$usr_all_domRoles=process_user_rhel_idm_ipa_rbac($username, $usr_all_domRoles);	
      	logDebug("Returned process_user_rhel_idm_ipa_rbac,, usr_all_domRoles='$usr_all_domRoles'");

    	if($usr_all_domRoles ne "") {
		$usr_all_domRoles="DOM_ROLE($usr_all_domRoles)";
      		logDebug("Report usr_all_domRoles privilege: '$usr_all_domRoles' ");
       		if($privField eq "") {
        		$privField = $usr_all_domRoles;
        	} else {
       			$privField = $privField . "," . $usr_all_domRoles;
       		}
    	}

      } #if for RHELIDMIPA ends here

    $username = "LDAP/" . $username;
    logDebug("Report: $username - Add LDAP prefix");
    if($Dormant eq "ON_ON") {
        $userllogon = "";
        $PWChg ="";
    } elsif($Dormant eq "ON_OFF") {
        $userllogon = "";
    }

  }
  
  if ( $IS_ADMIN_ENT_ACC != 0 && $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0)
  {
    if($local_users{$username} != 1)
    {

    #V9.7.0 added 
    if( $RHELIDMIPA == 1 )
    {
	my $usr_all_domRoles="";

      	logDebug("Calling Location B");
      	logDebug("Calling process_user_rhel_idm_ipa_rbac,,  user=$username, usr_all_domRoles='$usr_all_domRoles'");
    	$usr_all_domRoles=process_user_rhel_idm_ipa_rbac($username, $usr_all_domRoles);	
      	logDebug("Returned process_user_rhel_idm_ipa_rbac,, usr_all_domRoles='$usr_all_domRoles'");

    	if($usr_all_domRoles ne "") {
		$usr_all_domRoles="DOM_ROLE($usr_all_domRoles)";
      		logDebug("Report usr_all_domRoles privilege: '$usr_all_domRoles' ");
       		if($privField eq "") {
        		$privField = $usr_all_domRoles;
        	} else {
       			$privField = $privField . "," . $usr_all_domRoles;
       		}
    	}

      } #if for RHELIDMIPA ends here

      $username = "LDAP/" . $username;
      logDebug("Report: $username - Add LDAP prefix");
      if($Dormant eq "ON_ON") {
        $userllogon = "";
        $PWChg ="";
      } elsif($Dormant eq "ON_OFF") {
        $userllogon = "";
      }

    }

  }

if (($PROCESSLDAP || $IS_ADMIN_ENT_ACC == 2 || $IS_ADMIN_ENT_ACC == 3) || ( $IS_ADMIN_ENT_ACC != 0 && $NIS == 0 && $LDAP == 0 && $NOAUTOLDAP == 0)) {
   my @Sgroups=();
   foreach $Sgroup (split(/,/,$groupField)) { 
        logDebug("Check LDAP group: $groupField ");
  	if($local_groups{$Sgroup} != 1) {
      		$groupField = "LDAP/" . $Sgroup;
		push(@Sgroups,$groupField);
      		logDebug("Report group: $groupField - Add LDAP group prefix");
   	} else {
		push(@Sgroups,$Sgroup);
	}
   }

  $groupField = join(",", @Sgroups);
}  


if ($PROCESSNIS) {
   my @Sgroups=();
   foreach $Sgroup (split(/,/,$groupField)) {
        logDebug("Check NIS group: $groupField ");
        if($local_groups{$Sgroup} != 1) {
                $groupField = "NIS/" . $Sgroup;
                push(@Sgroups,$groupField);
                logDebug("Report group: $groupField - Add NIS group prefix");
        } else {
                push(@Sgroups,$Sgroup);
	}
   }

  $groupField = join(",", @Sgroups);
}
		
	if($username =~ /ldap\/.+/i) {
		logInfo("LDAP user id : $username is Enabled.");
		$userstate = "Enabled";
	}
  if($DLLD == 0)
  {
	if($username =~ /LDAP\/(\w*)/) {
		$useronly =$1
	} else {
		$useronly=$username;
	}
	$userllogon = get_last_logon_user_id_new_format($useronly);
  }
  else
  {
    $userllogon = "";
  }	
  # Write the line
  if($SCMFORMAT)
  #SCM9 hostname<tab>os<tab>auditdate<tab>account<tab>userIDconv<tab>state<tab>l_logon<tab>group<tab>privilege
  { 
    print OUTPUT_FILE "$HOSTNAME\t$OS\t$myAUDITDATE\t$username\t$usergecos\t$scm_userstate\t$userllogon\t$groupField\t$privField\n";
  }
  elsif($MEF2FORMAT)
  #MEF2 customer|system|account|userID convention data|group|state|l_logon|privilege
  {
    print OUTPUT_FILE "$URTCUST|$HOSTNAME|$username|$usergecos|$groupField|$userstate|$userllogon|$privField\n";
  }
  elsif($MEF4FORMAT)
  {
    print OUTPUT_FILE "U|$URTCUST|S|$HOSTNAME|$OSNAME|$username|$UICmode|$usergecos|$userstate|$userllogon|$groupField|$privField|$UID|$PWMaxAge|$PWMinAge|$PWExp|$PWChg|$PWMinLen|$PWNeverExpires\n";
    logDebug("Report: U|$URTCUST|S|$HOSTNAME|$OSNAME|$username|$UICmode|$usergecos|$userstate|$userllogon|$groupField|$privField|$UID|$PWMaxAge|$PWMinAge|$PWExp|$PWChg|$PWMinLen|$PWNeverExpires");
  }
  else
  #MEF3 \93customer|identifier type|server identifier/application identifier|OS name/Application name|account|UICMode|userID convention data|state|l_logon |group|privilege\94
  #
  {

    if($Dormant eq "ON_ON") {
	logDebug("lastpassword change current format: $PWChg");
	my $Final_LPC=check_lpwchg_date_format($PWChg);
	logDebug("lastpassword change  final format: $Final_LPC");

   	print OUTPUT_FILE "$URTCUST|S|$HOSTNAME|$OSNAME|$username||$usergecos|$userstate|$userllogon|$groupField|$privField|$Final_LPC\n";
    	logDebug("Report1: $URTCUST|S|$HOSTNAME|$OSNAME|$username||$usergecos|$userstate|$userllogon|$groupField|$privField|$Final_LPC");
    } elsif($Dormant eq "ON_OFF") {
   	print OUTPUT_FILE "$URTCUST|S|$HOSTNAME|$OSNAME|$username||$usergecos|$userstate|$userllogon|$groupField|$privField|\n";
    	logDebug("Report2: $URTCUST|S|$HOSTNAME|$OSNAME|$username||$usergecos|$userstate|$userllogon|$groupField|$privField|");
    } elsif($Dormant eq "OFF_OFF") { 
   	print OUTPUT_FILE "$URTCUST|S|$HOSTNAME|$OSNAME|$username||$usergecos|$userstate|$userllogon|$groupField|$privField\n";
    	logDebug("Report3: $URTCUST|S|$HOSTNAME|$OSNAME|$username||$usergecos|$userstate|$userllogon|$groupField|$privField");
    } else {
		
		logDebug("lastpassword change current format: $PWChg");
		my $Final_LPC=check_lpwchg_date_format($PWChg);
		logDebug("lastpassword change  final format: $Final_LPC");
		print OUTPUT_FILE "$URTCUST|S|$HOSTNAME|$OSNAME|$username||$usergecos|$userstate|$userllogon|$groupField|$privField|$Final_LPC\n";
    	logDebug("Report1 default ON_ON: $URTCUST|S|$HOSTNAME|$OSNAME|$username||$usergecos|$userstate|$userllogon|$groupField|$privField|$Final_LPC");
   	
    }
  
  }
  
} # end while

if( $KERB ==1 ) {
	if (-e $KERBCONF){
		logDebug("Found KERB File");
        	&GetGroupsforKerb1();
        	&GetKerbMembers();
      	} else {
		logDebug("Not Found KERB File");
        	&GetGroupsforKerb();
        	&GetKerbMembers();
        	&GetPermittedUsersAndGroups();
	}
	
        $KERBFlag=1;
        my %unique = ();
        foreach my $item (@KerbMem)
        {
                $unique{$item} ++;
        }
        @KerbMem = keys %unique;
        &parsesudoers();
        foreach $usr (@KerbMem) {
                $Kerb_Data = &GetKerbIDDesc($usr);
                logDebug("Kerb user:$usr, Desc:$Kerb_Data");
		$Fuid="";
		$Kuid="";
		$KUserState="";
		$Kgecos="";
                ($Fuid, $Kuid, $KUserState, $Kgecos) = split(/:/,$Kerb_Data);
		if ($Kuid eq "") {
			$Kuid=$usr;
		}
                $privField="";
                $SudoGroup="";
                if($user_privuser{$Kuid}) {
                        logDebug "Found privileged ID: $Kuid";
                        $privField=$Kuid;
                }
                if($user_privgroups{$Kuid}) {
                        $group_privs=$user_privgroups{$Kuid};
                        $groupValue="GRP($group_privs)";
                        if($privField eq "") {
                                $privField=$groupValue;
                        } else {
                                logDebug("Prv feild1:$privField, Sudo value:$SudoValue");
                                $privField=$privField.",".$groupValue;
                        }
                }


		if ($UserGroup{$Kuid})
        	{
                	$usersudogroups=$UserGroup{$Kuid};
                	logDebug("Report: userID $Kuid, sudousergroup $usersudogroups");
                	%hash=();
                	@cases = split(/,/,$usersudogroups);
                	$usersudogroups = ""; 
                	%hash = map { $_ => 1 } @cases;
                	$usersudogroups = join(",", sort keys %hash);

                	$SudoGroup="SUDO_GRP($usersudogroups)";
                	if($privField eq "")
                	{
                        	$privField=$SudoGroup;
                	}
                	else
                	{
                        	$privField=$privField.",".$SudoGroup;
                	}
        	}


		 if($UserAlias{$Kuid}) {
                        if($privField eq "") {
                                $privField=$UserAlias{$Kuid};
                        } else {
                                logDebug("Prv feild3:$privField, Alias:$UserAlias{$Kuid}");
                                $privField=$privField.",$UserAlias{$Kuid}";
                        }
                        $privField=$privField.")";
                }
                $SudoValue="";
                if ($UserList{$Kuid}) {
                        $sudo_user = "SUDO\_";
                        logDebug("else:$Kuid is priviliged user, So adding SUDO to prefix");
                        $SudoValue=$sudo_user.$Kuid;

                        if($privField eq "") {
                                $privField=$SudoValue;
                        } else {
                                logDebug("Prv feild4:$privField, Sudo value:$SudoValue");
                                $privField=$privField.",".$SudoValue;
                        }
                }

                $Kuserllogon = get_last_logon_user_id_new_format($Kuid);
                $Kuid="LDAP/$Kuid";
                $KGroup=$KerbUserIDData{$Fuid}{KGRP};
		@Kgrps=split(/,/,$KGroup);
                my $FinalPrivField="";
                my $Privgroup="";
                my @KerbPrivgroups=();
                foreach my $Egrp (@Kgrps) {
                logDebug("check for grp: $Egrp===$KerbGroupPriv{$Egrp}");
                        if($KerbGroupPriv{$Egrp} eq "privgroup") {
                                logDebug("Kerb group: $Egrp is priviliged");
                                $Privgroup = $privField.","."SUDO\_GRP($Egrp)";
                                push(@KerbPrivgroups,"$Privgroup");
                        }
                }
                if(scalar(@KerbPrivgroups)) {
                        $FinalPrivField = join(",", @KerbPrivgroups);
                        $FinalPrivField =~ s/^\s*,//g;
                } else {
                        $FinalPrivField = $privField;
                }

		if( $Kgecos =~ /IBM|Kyndryl/i ) {
                        print OUTPUT_FILE "$URTCUST|S|$HOSTNAME|$OSNAME|$Kuid||$Kgecos|$KUserState|$Kuserllogon|$KGroup|$FinalPrivField\n";
                        print "MEF3:$URTCUST|S|$HOSTNAME|$OSNAME|$Kuid||$Kgecos|$KUserState|$Kuserllogon|$KGroup|$FinalPrivField\n";
		}	

        }
}

if( $OULD ==1 ) {
		logDebug("Processing OULD users");
		&GetOracleUnifiedDirUsersAndGroups();
		logDebug("All OULD users:@LUNames");
		my $Ldapgrp;
		foreach my $luser (@LUNames) {
				my $OULDuser=$luser;
				my $OULDdesc=$OULD_USER_LIST{USER_DESC}->{$OULDuser};
				my $OULDgroup=$OULD_USER_LIST{USER_GROUPS}->{$OULDuser};
				my $OULDuserllogon = get_last_logon_user_id_new_format($OULDuser);
				logDebug("each user:$OULDuser,desc:$OULDdesc,group:$OULDgroup,llogon:$OULDuserllogon");
				my @allLgrps=split(/,/,$OULDgroup);
				$Ldapgrp="";
				foreach my $Eachgrp (@allLgrps) {
						if($Eachgrp eq "") {
                                $Ldapgrp="LDAP/$Eachgrp";
                        } else {
                                $Ldapgrp=$Ldapgrp.","."LDAP/$Eachgrp";
                        }
				}	
				logDebug("ldap group:$Ldapgrp");
				$privField="";
                $SudoGroup="";
                if($user_privuser{$OULDuser}) {
                        logDebug "Found privileged ID: $OULDuser";
                        $privField=$OULDuser;
                }
                if($user_privgroups{$OULDuser}) {
                        $group_privs=$user_privgroups{$OULDuser};
                        $groupValue="GRP($group_privs)";
                        if($privField eq "") {
                                $privField=$groupValue;
                        } else {
                                logDebug("Prv feild1:$privField, Sudo value:$SudoValue");
                                $privField=$privField.",".$groupValue;
                        }
                }


			if ($UserGroup{$OULDuser})
        	{
                	$usersudogroups=$UserGroup{$OULDuser};
                	logDebug("Report: userID $OULDuser, sudousergroup $usersudogroups");
                	%hash=();
                	@cases = split(/,/,$usersudogroups);
                	$usersudogroups = ""; 
                	%hash = map { $_ => 1 } @cases;
                	$usersudogroups = join(",", sort keys %hash);

                	$SudoGroup="SUDO_GRP($usersudogroups)";
                	if($privField eq "")
                	{
                        	$privField=$SudoGroup;
                	}
                	else
                	{
                        	$privField=$privField.",".$SudoGroup;
                	}
        	}


		 if($UserAlias{$OULDuser}) {
                        if($privField eq "") {
                                $privField=$UserAlias{$OULDuser};
                        } else {
                                logDebug("Prv feild3:$privField, Alias:$UserAlias{$OULDuser}");
                                $privField=$privField.",$UserAlias{$OULDuser}";
                        }
                        $privField=$privField.")";
                }
                $SudoValue="";
                if ($UserList{$OULDuser}) {
                        $sudo_user = "SUDO\_";
                        logDebug("else:$Kuid is priviliged user, So adding SUDO to prefix");
                        $SudoValue=$sudo_user.$OULDuser;

                        if($privField eq "") {
                                $privField=$SudoValue;
                        } else {
                                logDebug("Prv feild4:$privField, Sudo value:$SudoValue");
                                $privField=$privField.",".$SudoValue;
                        }
                }

                $OULDuser="LDAP/$OULDuser";
                
				@Lgrps=split(/,/,$OULDgroup);
                my $FinalPrivField="";
                my $Privgroup="";
                my @OULDPrivgroups=();
                foreach my $Egrp (@Lgrps) {
                logDebug("check for grp: $Egrp===$OULDGroupPriv{$Egrp}");
                        if($OULDGroupPriv{$Egrp} eq "privgroup") {
                                logDebug("ould group: $Egrp is priviliged");
                                $Privgroup = $privField.","."SUDO\_GRP($Egrp)";
                                push(@OULDPrivgroups,"$Privgroup");
                        }
                }
                if(scalar(@OULDPrivgroups)) {
                        $FinalPrivField = join(",", @OULDPrivgroups);
                        $FinalPrivField =~ s/^\s*,//g;
                } else {
                        $FinalPrivField = $privField;
                }
				$Ldapgrp =~ s/^,//g;
				print OUTPUT_FILE "$URTCUST|S|$HOSTNAME|$OSNAME|$OULDuser||$OULDdesc||$OULDuserllogon|$Ldapgrp|$FinalPrivField\n";
                print "OULD MEF3:$URTCUST|S|$HOSTNAME|$OSNAME|$OULDuser||$OULDdesc||$OULDuserllogon|$Ldapgrp|$FinalPrivField\n";
		}
		
}

if($MEF4FORMAT)
{
  report_group();
}

while (($key,$value) = each %UserList) {
  $SudoValue="";
  logMsg(WARN,"invalid user name $key in $SUDOERS");
}
} # end sub report

sub printsig()
{
  # V7.4 Code to print custom signature for dummy id
  if ($SIG_TSCM) {
    $NOTREALID = "NOTaRealID-TSCM";
  }
  elsif ($SIG_SCR) {
    $NOTREALID = "NOTaRealID-SCR";
  }
  elsif($SIG_TCM) {
    $NOTREALID = "NOTaRealID-TCM";
  }
  elsif($SIG_FUS) {
    $NOTREALID = "NOTaRealID-FUS";
  }
  else {
    $NOTREALID = "NOTaRealID";
  }
  
  if($SIGNATURE ne "")
  {
    $NOTREALID = "NOTaRealID$SIGNATURE";
  }
  
  my $TIMEZONE=getTimeZone();
  
  my $UATstr = "";
  
  if($UAT == 1)
  {
    $UATstr = Report_UAT();
  }
  my $Rootaccess;
  if($NOTROOT == 1)
  {
    $Rootaccess=NO;
  } else {
	$Rootaccess=YES;
  }
  ## Add dummy record to end of file
  if($SCMFORMAT)
  #SCM9 hostname<tab>os<tab>auditdate<tab>account<tab>userIDconv<tab>state<tab>l_logon<tab>group<tab>privilege
  {
    print OUTPUT_FILE "$HOSTNAME\t$OS\t$myAUDITDATE\t$NOTREALID\t000/V///$myAUDITDATE:FN=$0:VER=$VERSION:CKSUM=$CKSUM:SUDO=$SUDOVER:ROOT=$Rootaccess\t1\t\t\t\n";
  }
  elsif($MEF2FORMAT)
  #MEF2 customer|system|account|userID convention data|group|state|l_logon|privilege
  {
    print OUTPUT_FILE "$URTCUST|$HOSTNAME|$NOTREALID|000/V///$myAUDITDATE:FN=$0:VER=$VERSION:CKSUM=$CKSUM:SUDO=$SUDOVER:ROOT=$Rootaccess||||\n";
  }
  elsif ($MEF4FORMAT)
  {
    print OUTPUT_FILE "S|$URTCUST|S|$HOSTNAME|$OSNAME|$NOTREALID|$UATstr|000/V///$myAUDITDATE:FN=$0:VER=$VERSION:CKSUM=$CKSUM:SUDO=$SUDOVER:ROOT=$Rootaccess||$TIMEZONE|$knowpar|$EXIT_CODE|||||||\n";
  }
  else
  {
    
  	if($Dormant eq "ON_ON" || $Dormant eq "ON_OFF") {
    		print OUTPUT_FILE "$URTCUST|S|$HOSTNAME|$OSNAME|$NOTREALID|$UATstr|000/V///$myAUDITDATE:FN=$0:VER=$VERSION:CKSUM=$CKSUM:SUDO=$SUDOVER:ROOT=$Rootaccess||$TIMEZONE|$knowpar|$EXIT_CODE|\n";
   	} else {
    		print OUTPUT_FILE "$URTCUST|S|$HOSTNAME|$OSNAME|$NOTREALID|$UATstr|000/V///$myAUDITDATE:FN=$0:VER=$VERSION:CKSUM=$CKSUM:SUDO=$SUDOVER:ROOT=$Rootaccess||$TIMEZONE|$knowpar|$EXIT_CODE\n";
	}  
  }

  logInfo("$ErrCnt errors encountered");

  close OUTPUT_FILE || logAbort("Problem closing output file : $!");
  
  &Filter_mef3();
  
  if($OWNER ne "")
  {
    `chown $OWNER $OUTFILE`;
  }
}

####### V 7.5 ###############
sub Parse_LDAP_Netusr
{
#TLS
$attr_tls ="/tmp/tls.out";
if($TLS ==0 && $RHIM != 1) {  
    logDebug("Checking TLS certificate for LDAP BASE DN");
    `ldapsearch -x -H ldaps://$LDAPSVR:$LDAPPORT -b $LDAPBASE -Z > $attr_tls 2>&1`;
    logDebug("Command used to get TLS users :ldapsearch -x -b $LDAPBASE -H ldaps://$LDAPSVR:$LDAPPORT -Z ");
    open TLS_OUT, "$attr_tls" || logAbort("Can't open $attr_tls for reading : $!"); 
    while($out_line =<TLS_OUT>) {
    	logDebug("Parse_LDAP_TLS output: line = $out_line");
    	if ( $out_line =~ /TLS already started/i ) {
  	    logDebug("Found $& in the output...considering TLS certificate enabled");
            $TLS = 1 ;
        }
    }
} 
  
if($TLS ==0 && $RHIM != 1) {  
    logDebug("Checking TLS certificate for LDAP w/o BASE DN");
    `ldapsearch -x -b -H ldaps://$LDAPSVR -Z > $attr_tls 2>&1`;
    logDebug("Command used to get TLS users :ldapsearch -x -b -H ldaps://$LDAPSVR -Z ");
    open TLS_OUT, "$attr_tls" || logAbort("Can't open $attr_tls for reading : $!");
    while($out_line =<TLS_OUT>) {
    	logDebug("Parse_LDAP_TLS output: line = $out_line");
    	if ( $out_line =~ /TLS already started/i ) {
            logDebug("Found $& in the output...considering TLS certificate enabled");
            $TLS = 1 ;
        }
    }
}
  
  logDebug("Parse_LDAP_Netusr: userID = $_[0]");

if ( $NOAUTOLDAPENABLE == 1) {
	$TLS = 0;
}

if($TLS == 1) {
  	logDebug("process_TLS_LDAP_users: ");
        $attr=`ldapsearch -x -H ldaps://$LDAPSVR:$LDAPPORT -b $LDAPBASE -Z`;

  	logDebug("Command used to get TLS users:ldapsearch -x -H ldaps://$LDAPSVR:$LDAPPORT -b $LDAPBASE -Z ");
} else {
    if($LDAPFILE eq "")
    {
        $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT uid=$_[0] uid userPassword uidNumber gidNumber loginShell gecos description`;
    }
    else
    {
        $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT $LDAPADDITIONAL uid=$_[0] uid userPassword uidNumber gidNumber loginShell gecos description`;
    }
}
   
  if ( $? != 0 )
  {
    logAbort("1accessing LDAP server ($?)");
  }

  $username="";
  $passwd="";
  $uid="";
  $gid="";
  $gecos="";
  $shell="";
  
  foreach $line (split(/\n/,$attr))
  {
    logDebug("Parse_LDAP_Netusr: line = $line");
    if ( $line =~ /^uid:\s(\S+)/ ){
      $username =  $1 ;
      next;
    }
    if ( $line =~ /^userPassword::\s(\S+)/ ) {
      $passwd = $1;
      next;
    }
    if ( $line =~ /^uidNumber:\s(\d+)/ ) {
      $uid = $1;
      next;
    }
    if ( $line =~ /^gidNumber:\s(\d+)/ ) {
      $gid  = $1;
      next;
    }
    if ( $line =~ /^loginShell:\s(\S+)/ ) {
      $shell  = $1;
      next;
    }
    if ( $line =~ /^gecos:\s(.*)$/ ) {
      $gecos = $1;
      next;
    }
    if ( $line =~ /^description:\s(.*)$/ && $gecos eq "") {
        $gecos = $1;
      next;
    }
    
  } #End foreach

  logDebug("Parse_LDAP_Netusr: user=$username:$passwd:$uid:$gid:$gecos");
  
  if($username ne "" && $gid ne "")
  {
    if (exists $primaryGroupUsers{$gid})
    {
      $primaryGroupUsers{$gid} = $primaryGroupUsers{$gid} . "," . $username;
    }
    else
    {
      $primaryGroupUsers{$gid} = $username;
    }
  }
  else
  {
    logDebug("Parse_LDAP_Netusr: no LDAP record for $_[0]");
  }
  `rm -f $attr_tls`;
}

sub Parse_LDAP_Subnetgrp
{
  my $Netgrp = shift;
  my $memlist = "";
  my $tmpattr="";
  
  if($LDAPFILE eq "")
  {
    $tmpattr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT cn=$Netgrp cn nisNetgroupTriple memberNisNetgroup`;
  }
  else
  {
    $tmpattr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASEGROUP -p $LDAPPORT $LDAPADDITIONAL cn=$Netgrp cn nisNetgroupTriple memberNisNetgroup`;
  }
  
  if ( $? != 0 )
  {
    logAbort("2accessing LDAP server ($?)");
  }
 
  logDebug("Subgroup Found: $Netgrp: $tmpattr");

  foreach $line (split(/\n/,$tmpattr))
  {
    logDebug("Parse_LDAP_Subnetgrp: read = $line");
    if ($line =~ /^memberNisNetgroup:\s(\S+)/ )
    {
      my $tmpmemlist=Parse_LDAP_Subnetgrp($1);
      if ($memlist eq "" )
      {
        $memlist =  $tmpmemlist;
      }
      else
      {
        $memlist = $memlist .  ",$tmpmemlist";
      }
      next;
    }
    
    if ( $line =~ /^nisNetgroupTriple:\s\(,(\S+),/ ){
      if ($memlist eq "" ) {
        $memlist =  $1 ;
      }
      else {
        $memlist = $memlist .  ",$1" ;
      }
    }
  }
  return $memlist;
}

sub Parse_LDAP_Netgrp
{
  ($Netgrp) = $_[0] =~ /^\+\@(\S+)/;
  logDebug("Parse_LDAP_Netgrp: group = $Netgrp");
  $ldapmemlist = "";
  if($LDAPFILE eq "")
  {
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT cn=$Netgrp cn nisNetgroupTriple memberNisNetgroup`;
  }
  else
  {
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASEGROUP -p $LDAPPORT $LDAPADDITIONAL cn=$Netgrp cn nisNetgroupTriple memberNisNetgroup`;
  }
  
  if ( $? != 0 )
  {
    logAbort("3accessing LDAP server ($?)");
  }
  
  logDebug("Netgroup Found: $_[0], $Netgrp: $attr");

  foreach $line (split(/\n/,$attr))
  {
    if ($line =~ /^memberNisNetgroup:\s(\S+)/ )
    {
      my $tmpmemlist=Parse_LDAP_Subnetgrp($1);
      if ($ldapmemlist eq "" )
      {
        $ldapmemlist =  $tmpmemlist;
      }
      else
      {
        $ldapmemlist = $ldapmemlist .  ",$tmpmemlist";
      }
      next;
    }

    if ( $line =~ /^nisNetgroupTriple:\s\(,(\S+),/ )
    {
      if ($ldapmemlist eq "" )
      {
        $ldapmemlist =  $1 ;
      }
      else
      {
        $ldapmemlist = $ldapmemlist .  ",$1" ;
      }
    }
  }
  logDebug("Members of $Netgrp is $ldapmemlist");

  foreach $username (split(/,/,$ldapmemlist))
  {
    if(exists $user_gid{$username})
    {
      if(exists $netgrouplist{$Netgrp})
      {
        $netgrouplist{$Netgrp} = $netgrouplist{$Netgrp} . ",$username";
      }
      else
      {
        $netgrouplist{$Netgrp} = $username;
      }
      next;
    }
    else
    {
      Parse_LDAP_Netusr($username);
    }

    if(exists $netgrouplist{$Netgrp})
    {
      $netgrouplist{$Netgrp} = $netgrouplist{$Netgrp} . ",$username";
    }
    else
    {
      $netgrouplist{$Netgrp} = $username;
    }
    parse_user_info;
  }
}

sub parse_ldapgp
{
  logInfo("Processing LDAP groups");
  my $LDGHASH = get_ldgrp();
  for my $groupid ( keys %$LDGHASH )
  {
    $memlist = $LDGHASH->{ $groupid }->{ 'gmemlist' } ;
    $gname = $LDGHASH->{ $groupid }->{ 'gname' } ;
    logDebug("Primary Group users of $groupid is $primaryGroupUsers{$groupid}");
    if (exists $primaryGroupUsers{$groupid})
    {
      if($memlist eq "")
      {
        $allusers=$primaryGroupUsers{$groupid};
      }
      else
      {
        $allusers="$primaryGroupUsers{$groupid},$memlist";
      }
    }
    else
    {
      $allusers=$memlist;
    }
    
    $FOUNDPG=is_priv_group($gname, $groupid);
    
    logDebug("All users $gname: $allusers");
    logDebug("FOUNDPG:$FOUNDPG");

    foreach $username (split(/,/,$allusers))
    {
      if (exists $user_allgroups{$username})
      {
        my $is_founded_dublicate = 0;
        foreach my $usergroup (split(/,/,$user_allgroups{$username})){
        if ($usergroup eq $gname){
          $is_founded_dublicate = 1;
        }
      }

      if (!$is_founded_dublicate){
        $user_allgroups{$username} = $user_allgroups{$username} . "," . $gname;
      }
    }
    else
    {
      $user_allgroups{$username} = $gname;
    } # end if

    if ($FOUNDPG)
    # only save priv groups
    {
      logDebug("ADDING priv group $gname");
      if (exists $user_privgroups{$username})
      {
        $user_privgroups{$username} = $user_privgroups{$username} . "," . $gname;
      }
      else
      {
        $user_privgroups{$username} = $gname;
      } # end if
    } # end if

  } # end foreach

}#end for

}

sub get_ldgrp
{
  my %LDGRPS = ( );
  my $LDAPTLS=0;
my $ldaptmp="/tmp/ldap_group";
if($TLS == 1) {
	
        logDebug("process_TLS_LDAP_groups: ");
	if($LDAPFILE eq "" )
  	{
    		`$LDAPCMD -H ldaps://$LDAPSVR -b $LDAPBASE -p $LDAPPORT objectClass=posixGroup  cn gidNumber memberUid -Z > $tmpfile `;
			logDebug("Command used to get LDAP Group1:$LDAPCMD -H ldaps://$LDAPSVR -b $LDAPBASE -p $LDAPPORT objectClass=posixGroup  cn gidNumber memberUid -Z");
			if ( $? != 0 )
			{
				`$LDAPCMD -H ldaps://$LDAPSVR:$LDAPPORT -b $LDAPBASE objectClass=posixGroup  cn gidNumber memberUid -Z > $tmpfile `;
				$LDAPTLS = 1;
				logDebug("Command used to get LDAP Group1.1:$LDAPCMD -H ldaps://$LDAPSVR:$LDAPPORT -b $LDAPBASE objectClass=posixGroup  cn gidNumber memberUid -Z");
			}
  	} 
  	else
 	 {
    		`$LDAPCMD -H ldaps://$LDAPSVR -b $LDAPBASEGROUP -p $LDAPPORT $LDAPADDITIONAL objectClass=$LDAPGROUPOBJCLASS cn gidNumber memberUid -Z > $tmpfile `;
		
	    logDebug("Command used to get LDAP Group2:$LDAPCMD -H ldaps://$LDAPSVR -b $LDAPBASEGROUP -p $LDAPPORT $LDAPADDITIONAL objectClass=$LDAPGROUPOBJCLASS cn gidNumber memberUid -Z");
		 	
  	}

} else {

  	if($LDAPFILE eq "" && $LDAPNULL != 1)
  	{
    		`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT objectClass=posixGroup  cn gidNumber memberUid > $tmpfile `;

	    logDebug("Command used to get LDAP Group3:$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT objectClass=posixGroup  cn gidNumber memberUid");
  	} else {
		if($RHIM == 1 ) { 
			logDebug("Collecting LDAP Groups for Red hat Identity Manager");
			`ldapsearch -h $LDAPSVR -W -p $LDAPPORT -b $LDAPBASEGROUP $LDAPADDITIONAL > $tmpfile`;
			logDebug("ldapsearch -h $LDAPSVR -W -p $LDAPPORT -b $LDAPBASEGROUP $LDAPADDITIONAL");
		
		} elsif ($LDAPNULL == 1) {
				
			`ldapsearch cn gidNumber member> $ldaptmp`;
			
			logDebug("Command used to get LDAP Group: ldapsearch cn gidNumber member");
			open INFILE, "$ldaptmp"  || logAbort("Error on ldap");
			open OUTFILE, ">$tmpfile" || logAbort("Can't open $ldaptmp for writing : $!");
			my $EnableUser=0;
			while (my $group_line=<INFILE>) {
				if($group_line =~ /^dn:\suid*/ ) {
					$EnableUser = 1;
					next;
				} 
				if($EnableUser == 1 ) {
					if($group_line =~ /^cn:\s.*/) {
						next;
					}
				}
				if($EnableUser == 1 ) {
					if($group_line =~ /^gidNumber:\s.*/) {
						$EnableUser = 0;
						next;
					}
				}
			
			print OUTFILE $group_line;
			}
			
			
		}
		else { 
    			`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASEGROUP -p $LDAPPORT $LDAPADDITIONAL objectClass=$LDAPGROUPOBJCLASS cn gidNumber memberUid > $tmpfile `;

	    		logDebug("Command used to get LDAP Group4: $LDAPCMD -LLL -h ldaps://$LDAPSVR -b $LDAPBASEGROUP -p $LDAPPORT $LDAPADDITIONAL objectClass=$LDAPGROUPOBJCLASS cn gidNumber memberUid -Z");
		}
  	}
}  
  if ( $? != 0 )
  {
    logAbort("4accessing LDAP server ($?)");
  }
  
  $gName=$gidNum=$memlist="";
  
  open LDAP_FILE, "$tmpfile"  || logAbort("Error on ldap");
  open LDAP_GROUP_FILE, ">$LDAPGROUP" || logAbort("Can't open $LDAPGROUP for writing : $!");

   while (<LDAP_FILE>)
  {
    if ( /^\s/ )
    {
      logDebug("LDAP Group:$gName:$gidNum:$memlist");
      print LDAP_GROUP_FILE "$gName: :$gidNum:$memlist\n";
      $gName=$gidNum=$memlist="";
      next;
    }

    if ( /^cn:\s(\S+)/ )
    {
      $gName =  $1;
      if($RHIM != 1) {
        $memlist = "";
      }
      next;
    }

    if (/^gidNumber:\s(\d+)/)
    {
      $gidNum = $1;
      next;
    }


 if($RHIM ==1 || $LDAPNULL == 1 || $LDAPTLS == 1) {
    #  logDebug("member: Redhat identity manager Enabled");
        if ( /^member:\suid=(\w+)/ )
        {
                if ( $memlist eq "" )
                {
                        $memlist = "$1";
                } else {
                        $memlist = $memlist . ",$1";
                }
                next;
        }


    } else {
        if ( /^memberUid:\s(\w+)/ )
        {
                if ( $memlist eq "" )
                {
                        $memlist = "$1";
                } else {
                        $memlist = $memlist . ",$1";
                }
                next;
        }
    }
  }
  close LDAP_FILE;
  close LDAP_GROUP_FILE;
 `rm -f $tmpfile` ;
 `rm -f $ldaptmp`;
  return \%LDGRPS;
}

sub is_adminent_accessible()
{
  if($IS_ADMIN_ENT_ACC == 0)
  {
    if ( $OSNAME =~ /aix/i && $LDAP == 1 )
    {
      `lsuser -R LDAP ALL  2>&1`;
      if ($?)
      {
        logInfo("Server $HOST ($OSNAME) is not LDAP connected");
      }
      else
      {
        $IS_ADMIN_ENT_ACC = 1;
      }
    }
    
    if ( ($OSNAME =~ /linux/i || $OSNAME =~ /sunos/i || $OSNAME =~ /solaris/i) && ($NOAUTOLDAP == 0 || $LDAP == 1) )
    {
      `getent passwd`;
      if ($?)
      {
        logInfo("Checking on the admin ent tools . Operating system: $OSNAME is not supported");
      }
      else
      {
        $IS_ADMIN_ENT_ACC = 1;
      }
    }
  }
  logDebug("is_adminent_accessible = $IS_ADMIN_ENT_ACC");
}

sub check_pam()
{
  my $line="";
  my $ret=0;
  
  if($DEV == 1)
  {
    $LDAPCONF="./ldap.conf";
  }
  
  if ( -e $LDAPCONF && $OSNAME !~ /aix/i) 
  {
    open LDAPCONF_FILE, $LDAPCONF || logMsg(WARN,"Can't open $LDAPCONF : $!");
    while ($line = <LDAPCONF_FILE>)
    {
      if ($line =~ /^#/)  
      {
        next;
      }
      
      if ($line =~ /\s*pam_check_host_attr\s*yes/)
      {
        $ret=1;
        logDebug("pam_check_host_attr yes");
        last;
      }
    }
    close LDAPCONF_FILE;
  }
  else
  {
    logDebug("check_pam: Found AIX or $LDAPCONF is not accessible");
  }
  return $ret;
}

sub process_LDAP_users()
{
#TLS
$attr_tls ="/tmp/tls.out"; 
 my $isPAM=check_pam();
if($TLS ==0 && $RHIM != 1) {
    logDebug("Checking TLS certificate for LDAP BASE DN");
    `ldapsearch -x -H ldaps://$LDAPSVR:$LDAPPORT -b $LDAPBASE -Z > $attr_tls 2>&1`; 
    logDebug("Command used to get TLS users :ldapsearch -x -b $LDAPBASE -H ldaps://$LDAPSVR:$LDAPPORT -Z ");
    open TLS_OUT, "$attr_tls" || logAbort("Can't open $attr_tls for reading : $!");
    while($out_line =<TLS_OUT>) {  
        logDebug("Parse_LDAP_TLS output: line = $out_line");
        if ( $out_line =~ /TLS already started/i ) {
            logDebug("Found $& in the output...considering TLS certificate enabled");
            $TLS = 1 ;
        }
    }
}

if($TLS ==0 && $RHIM != 1) {
    logDebug("Checking TLS certificate for LDAP w/o BASE DN");
   `ldapsearch -x -b -H ldaps://$LDAPSVR -Z > $attr_tls 2>&1`;
    logDebug("Command used to get TLS users :ldapsearch -x -b -H ldaps://$LDAPSVR -Z ");
    open TLS_OUT, "$attr_tls" || logAbort("Can't open $attr_tls for reading : $!");
    while($out_line =<TLS_OUT>) {
        logDebug("Parse_LDAP_TLS output: line = $out_line");
        if ( $out_line =~ /TLS already started/i ) {
            logDebug("Found $& in the output...considering TLS certificate enabled");
            $TLS = 1 ;
        }
    }
}

if ( $NOAUTOLDAPENABLE == 1) {
        $TLS = 0;
}

  logDebug("process_LDAP_users: check_pam=$isPAM");
if($TLS == 1) {

  	logDebug("process_TLS_LDAP_users: ");

        $attr=`ldapsearch -x -H ldaps://$LDAPSVR:$LDAPPORT -b $LDAPBASE -Z`;
	
  	logDebug("Command used to get TLS users :ldapsearch -x -H ldaps://$LDAPSVR:$LDAPPORT -b $LDAPBASE -Z ");
} else {

  if($LDAPFILE eq "" && $LDAPNULL != 1)
  {
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT uid=* uid userpassword uidNumber gidNumber loginShell gecos host description`;
	logDebug("LDAP COmmand: $LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT uid=* uid userpassword uidNumber gidNumber loginShell gecos host description");
  } elsif ($LDAPNULL == 1) {
  
	$attr=`$LDAPCMD -LLL  uid=* uid userpassword uidNumber gidNumber loginShell gecos host description`;
    logDebug("LDAP COmmand: $LDAPCMD -LLL  uid=* uid userpassword uidNumber gidNumber loginShell gecos host description");
  }
  else
  {
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT $LDAPADDITIONAL $LDAPUSERFILTER uid userpassword uidNumber gidNumber loginShell gecos host description`;
	logDebug("LDAP COmmand: $LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT $LDAPADDITIONAL $LDAPUSERFILTER uid userpassword uidNumber gidNumber loginShell gecos host description");
	
  }
}

  if ( $? != 0 )
  {
#    logAbort("5accessing LDAP server ($?)");
logInfo("5accessing LDAP server ($?)");
  }
  my $firstTime = 0;
  $username = $passwd = $uid = $gid = $shell = $gecos = "";
  my $isAIX=$OSNAME =~ /aix/i;
  my $checkHost=0;
   
  open LDAP_PASSWD, ">$LDAPPASSWD" || logAbort("Can't open $LDAPPASSWD for writing : $!");
  
  foreach $line (split(/\n/,$attr))
  {
    logDebug("process_LDAP_users: line=$line");
    
    if ( $line =~ /^userPassword::?\s(\S+)/ ) {
      $passwd = $1;
      next;
    }
    if ( $line =~ /^uidNumber:\s(\d+)/ ) {
		if ($LDAPNULL == 1) {
			$gid = $1;
		} else {
			$uid = $1;
		}
      next;
    }
    if ( $line =~ /^gidNumber:\s(\d+)/ ) {
		if ($LDAPNULL == 1) {
			$uid  = $1;
		} else {
			$gid = $1;
		}
      
      next;
    }
    if ( $line =~ /^loginShell:\s(\S+)/ ) {
      $shell  = $1;
      next;
    }
    if ( $line =~ /^gecos:\s(.*)$/) {
      $gecos = $1;
      next;
    }
    if ( $line =~ /^description:\s(.*)$/ && $gecos eq "") {
      $gecos = $1;
      next;
    }
    if ( $line =~ /^uid:\s(.*)$/ ) {
      $username = $1;
      next;
    }
    
    if ( $line =~ /^host:\s(\S+)/ )
     {
      my $_host=lc $1;
      if($isPAM == 1 && (($_host eq $HOST) || ($_host eq $LONG_HOST_NAME)))
      {
        $checkHost=1;
        logDebug("process_LDAP_users: host $_host");
      }
      next;
    }

    if ( $line =~ /^dn:\s/ )
    {
      logDebug("process_LDAP_users: LDAP user=$username");
      if($firstTime == 0 )
      {
        $firstTime = 1;
        next;
      }
      
      if($uid eq "" && $gid eq "")
      {
        $passwd = $uid = $gid = $shell = $gecos = "";
        $checkHost=0;
        next;
      }
      
      if($isAIX)
      {
        if($LDAP_users{$username} == 1)
        {
          if ($passwd =~ /^\*/ )
          {
            $AIX_passwd_state{$username} = "Disabled";
            $scm_user_state{$username} = "1";
            logDebug("process_LDAP_users $username Disabled: password=$passwd in userPassword field");
          }
          else
          {
            $AIX_passwd_state{$username} = "Enabled";
            $scm_user_state{$username} = "0";
            logDebug("process_LDAP_users $username Enabled: password=$passwd in userPassword field");
          }
          print LDAP_PASSWD "$username:$passwd:$uid:$gid:$gecos: :$shell\n";
        }
        else
        {
          logDebug("process_LDAP_users: skip user $username");
        }
      }
      else
      {
       if($isPAM)
        {
          if($checkHost == 1)
          {
            print LDAP_PASSWD "$username:$passwd:$uid:$gid:$gecos: :$shell\n";
          }
          else
          {
            logDebug("process_LDAP_users: skip user $username");
          }
        }
        else
        {
          print LDAP_PASSWD "$username:$passwd:$uid:$gid:$gecos: :$shell\n";
        }
      }
      $passwd = $uid = $gid = $shell = $gecos = "";
      $checkHost=0;
    }
  }

  if($uid ne "")
  {
    if($isAIX)
    {
      if($LDAP_users{$username} == 1)
      {
        print LDAP_PASSWD "$username:$passwd:$uid:$gid:$gecos: :$shell\n";
      }
      else
      {
       logDebug("process_LDAP_users: skip user $username");
      }
    }
    else
    {
     if($isPAM)
      {
        if($checkHost == 1)
        {
          print LDAP_PASSWD "$username:$passwd:$uid:$gid:$gecos: :$shell\n";
        }
        else
        {
          logDebug("process_LDAP_users: skip user $username");
        }
      }
      else
      {
        print LDAP_PASSWD "$username:$passwd:$uid:$gid:$gecos: :$shell\n";
      }
    }
  }
  close LDAP_PASSWD;
  `rm -f $attr_tls`;
}

sub check_nisplus
{
   #my $proc = `ps -ef | grep nis_cachemgr`;
   my $ret = 0;
   #if ( -e "/var/nis/NIS_COLD_START" and $ret=~ /nis_cachemgr/)
   if ( -e "/var/nis/NIS_COLD_START" )
   {
      $ret = 1;
   }
   return $ret;
}

sub preparsesudoers()
{
  my $sudo_file=shift;
  my $tmp_sudo_file=shift;
    
  logDebug("Preprocess sudo file $sudo_file");
  `cat $sudo_file >> $tmp_sudo_file`;
  my $sudohandler = IO::File->new($sudo_file)  || logMsg(WARN, "Can't open SUDOERS: $sudo_file");
  my $include_file;
  while ($nextline = <$sudohandler>)
  {
    chomp $nextline;
    if ( $nextline =~ /^#include\s(.*)$/i )
    {
      $include_file = $1;
     
      if ( $include_file =~ /(.*)%h$/i )
      {
        $include_file = $1.$HOST;
        logDebug("SUDOERS: Add host name to sudo file $include_file");
      }
      
      if( ! -e $include_file)
      {
        logDebug("SUDOERS:$include_file is not a file");
        next;
      }
      
      logDebug("SUDOERS: Found #include directive. Included file name is $include_file");
      &preparsesudoers($include_file, $tmp_sudo_file);
    }
   if ( $nextline =~ /^#includedir\s(.*)$/i )
    {
      $include_dir = $1;
      $include_dir=trim($include_dir); 
      if($include_dir !~ /\/$/)
      {
        $include_dir.="/";
      }
      
      if(!opendir(SUDO_DIR, $include_dir))
      {
        logMsg(WARN, "SUDOERS: Can't open directory $include_dir");
        next;
      }
      
      while ($include_file = readdir(SUDO_DIR))
      {
        if( $include_file =~ /^\.\.?$/)
        {
          logDebug("SUDOERS: 1 Skip file $include_file");
          next;
        }
         
        if( $include_file =~ /~$/i || $include_file =~ /\./i)
        {
          logDebug("SUDOERS: 2 Skip file $include_file");
          next;
        }
          
        $include_file=$include_dir.$include_file;
          
        if( -d $include_file)
        {
          logDebug("SUDOERS:Skip directory $include_file");
          next;
        }

        &preparsesudoers($include_file, $tmp_sudo_file);
      }
      closedir(SUDO_DIR);
      logDebug("SUDOERS:Found #includedir directive. Included directory name is $include_dir");
    }
  }
}

sub trim($)
{
    my $str = shift;
    $str =~ s/^\s+//;
    $str =~ s/\s+$//;
    return $str;
}


sub mef_users_post_process
{
    my $OUTPUTFILE = shift;
    my $ibmOnly = shift;
    my $customerOnly = shift;
    my $non_customer_only = shift;
    my $user;
    my $GECOS;

    logDebug("mef_users_post_process:$non_customer_only");
    if(($ibmOnly == $customerOnly) && ($non_customer_only == 0))
    {
        return 1;
    }
    
    my $isIbmUser = 0;
	my $iscustomerID = 0;
    my $base_mef_name = `basename $OUTPUTFILE`;
    $base_mef_name=trim($base_mef_name);
    my $TMP_OUT = "/tmp/${base_mef_name}_tmp";
    
    `cat $OUTPUTFILE > $TMP_OUT`;
    if(!open TMP_OUT_FILE, $TMP_OUT)
    {
      unlink $TMP_OUT;
      logAbort("Can't open TMP_OUT_FILE '$TMP_OUT'");
      #$EXIT_CODE=EXEC_WARN;
      #$ErrCnt++;
      return 0;
    }
    # open file for writing
    if(!open OUT_MEF_FILE, ">$OUTPUTFILE")
    {
      unlink $TMP_OUT;
      logAbort("Can't open OUTPUTFILE '$OUTPUTFILE'");
      #$EXIT_CODE=EXEC_WARN;
      #$ErrCnt++;
      return 0;
    }
    while (<TMP_OUT_FILE>)
    {
        my $line = $_; 
        $line=trim($line);
	if($Dormant =~ /ON_ON|ON_OFF/) {

    		#  logDebug("mef_users_post_process:ON_ON|ON_OFF is enabled");
		if (!($line =~ /([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)$/))
        	{
	    
      	    		logDebug("Report: mef_users_post_process:ON_ON|ON_OFF");
            		print (OUT_MEF_FILE "$line\n");
            		next;
       	 	}

        	$user  = $5;
        	$GECOS = $7;

	} else {
        	if (!($line =~ /([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)$/))
        	{
      	    		logDebug("Report: mef_users_post_process:OFF_OFF");
            		print (OUT_MEF_FILE "$line\n");
            		next;
        	}
        	$user  = $5;
        	$GECOS = $7;
	}
        if($user =~ /^NOTaRealID.*/i) # NOTaRealID
        {
            print (OUT_MEF_FILE "$line\n");
            next;
        }
        if(($user=~/^[^@]*@[^\.]*\.ibm\.com$/i || $user =~ /^[^@]*\@kyndryl\.com$/) && $ibmOnly == 1)
        {
                print (OUT_MEF_FILE "$line\n");
            next;
        }

	if($non_customer_only == 0)
        {
        	if( ($GECOS=~/\w{2,3}\/[^\/]*\/[^\/]*\/[^\/]*\/.*/i) == 0 )
        	{
            		#print "   --->  NOT AG FORMAT --- \n";
            		$GECOS = get_urt_format($GECOS);
            		#print "         ... GOT AG FORMAT --- ($GECOS)\n";
        	}
        	if( ($GECOS=~/\w{2,3}\/[^\/]*\/[^\/]*\/[^\/]*\/.*/i) == 0 )
        	{
            		logMsg(WARN,"Can't found URT Format $user:'$GECOS'");
            		next;
        	}
	}
        $isIbmUser = ( $GECOS=~/\w{2,3}\/([ISFTENK])\/[^\/]*\/[^\/]*\/.*/i);
	$iscustomerID = ( $GECOS=~/\w{2,3}\/([CV])\/[^\/]*\/[^\/]*\/.*/i);
        #print "   --- FOUND IBM SYMBOL [$1] --- \n";
	if($iscustomerID==0 && $non_customer_only == 1)
        {
      	    logDebug("Report: mef_users_post_process: except customerids :$line");
            print (OUT_MEF_FILE "$line\n");
            next;
        }
		
        if( ($isIbmUser==1 && $ibmOnly == 1) )
        {
      	    logDebug("Report: mef_users_post_process: kyndryl only ids");
            print (OUT_MEF_FILE "$line\n");
            next;
        }
        if($isIbmUser==0 && $customerOnly)
        {
      	    logDebug("Report: mef_users_post_process: customer only ids");
            print (OUT_MEF_FILE "$line\n");
            next;
        }
    }
    close TMP_OUT_FILE;
    close OUT_MEF_FILE;
    unlink $TMP_OUT;
    return 1;
}

sub Filter_mef3
{
  logDebug("filter: OutputFile:$OUTFILE");
  logDebug("filter: kyndrylOnly:$ibmonly"); 
  logDebug("filter: customerOnly:$customeronly");
  logDebug("filter: customerOnly:$noncustomeronly");
  if( $ibmonly != 0 || $customeronly != 0 || $noncustomeronly != 0 )
  {
    logDebug("calling mef_users_post_process functio: $noncustomeronly");
    mef_users_post_process( $OUTFILE,$ibmonly,$customeronly,$noncustomeronly );
  }
}

sub collect_LDAP_users_aix
{
  my $tmp_user_file="/tmp/ldapuser_tmp";
  
  my $nextline;
  my $username="";
  
  if($OSNAME =~ /aix/i)
  { 
    $attr=`lsuser -R LDAP ALL > $tmp_user_file`;
    if ( $? != 0 )
    {
      return;
    }
    
    open TMP_USER_FILE, $tmp_user_file || logMsg(WARN,"Can't open $tmp_user_file");
    while ($nextline = <TMP_USER_FILE>)
    {
      chomp($nextline);
    
      my $cmt_ix = index( $nextline, " ");
      if ( $cmt_ix >= 0 )
      {
        if($nextline =~ /registry=LDAP.*SYSTEM=.*LDAP.*\s/)
        {
          $username = substr( $nextline, 0, $cmt_ix);
          logDebug("collect_LDAP_users_aix : Add LDAP user $username");
          $LDAP_users{$username}=1;
        }
      }
    } # end while
    
    close TMP_USER_FILE;
    `rm -f $tmp_user_file`;
  }
}

sub getfqdn($)
{
  my $hostname = shift;
  my $conffile="/etc/resolv.conf";
  my $line="";
  my $fqdn="";

  if($DEV == 1)
  {
    $conffile="./resolv.conf";
  }
  
  open RESOLV_FILE, $conffile || logMsg(WARN,"Can't open $conffile : $!");
  while ($line = <RESOLV_FILE>)
  {
    logDebug("getfqdn: read $line");
    if ($line =~ /^domain\s*(.*)$/i)
    {
      $fqdn="$hostname.$1";
      last;
    }
  }
  close RESOLV_FILE;
    
 # if($fqdn eq "")
  #{
   # $fqdn = `nslookup $hostname | awk '/^Name:/{print \$2}'`;
   # logDebug("getfqdn: nslookup $fqdn");
  #}
    
  if($fqdn eq "")
  {
    $fqdn=$hostname;
  }
    
  return lc trim($fqdn);
}
##############################################################
#GSA
##############################################################
#args filename, findwhat
#1- found
#0- not found
sub isThere
{
  my $FILENAME = shift;
  my $FINDWHAT = shift;
  
  logDebug("isThere : FILENAME=$FILENAME, FINDWHAT=$FINDWHAT");
  open FILE_FILE, $FILENAME || return 0;
  logDebug("isThere : Loading");
  while ($line = <FILE_FILE>)
  {
    if ($line =~ /$FINDWHAT/i)
    {
      #logDebug("isThere : found=$line");
      logDebug("isThere : found");
      close FILE_FILE;
      return 1;
      
    }
  }
  close FILE_FILE;
  logDebug("isThere : not found");
  return 0;
}

sub getFromThere
{
  my $FILENAME = shift;
  my $FINDWHAT = shift;
  my $ret="";
  
  logDebug("getFromThere : FILENAME=$FILENAME, FINDWHAT=$FINDWHAT");
  open FILE_FILE, $FILENAME || return $ret;
  logDebug("getFromThere : Loading");
  while ($line = <FILE_FILE>)
  {
    if ($line =~ /$FINDWHAT/i)
    {
      $ret=$1;
      last;
    }
  }
  close FILE_FILE;
  logDebug("getFromThere : return value=$ret");
  return $ret;
}

sub isThereDir
{
  my $DIR_NAME = shift;
  my $FILENAME_MASK = shift;
  my $FINDWHAT = shift;
  my $filename="";
  
  logDebug("isThereDir:$DIR_NAME $FILENAME_MASK $FINDWHAT");
  opendir(DIR_HANDLE, $DIR_NAME) || logMsg(WARN, "isThereDir: Can't open directory $DIR_NAME");
  while (defined ($filename = readdir(DIR_HANDLE)) )
  {
    if($filename =~ /$FILENAME_MASK/i)
    {
      if(isThere("$DIR_NAME$filename", $FINDWHAT) == 1)
      {
        closedir(DIR_HANDLE);
        return 1;
      }
    }
  }
  closedir(DIR_HANDLE);
  
  return 0; 
}

sub checkGSAconfig
{
  my $flag=0;
  my $METHODCFG="/usr/lib/security/methods.cfg";
  if($DEV == 1)
  {
    $METHODCFG="cfg/methods.cfg";
  }
  
  logDebug("checkGSAconfig: check configuration");
  
  if($OSNAME =~ /aix/i)
  {
    $flag = isThere($SUSER, "^[^\\*]\\s*SYSTEM.+gsa") && isThere($METHODCFG, "GSA");
  }  
  
  if($OSNAME =~ /linux/i)
  {
    my @checkFileList=("system-auth", "common-auth", "local-auth", "ftp", "login", "rexec", "rlogin", "samba", "sshd", "su", "sudo", "xscreensaver", "xdm", "gnome-screensaver");
    foreach $checkFile (@checkFileList)
    {
      if(isThere("/etc/pam.d/$checkFile", ".+gsa") == 1)
      {
        $flag = isThere("/etc/nsswitch.conf", "ldap");
        last;
      }
    }
    if($flag == 0)
    {
      $flag=isThereDir("/etc/security/", "^pam", ".+gsa");
    }
  }
  logDebug("checkGSAconfig: return value is $flag");
  return $flag;
} 

sub GSALDAP
{
  my $LDAPServer="";
  
  logDebug("GSALDAP: get LDAP server address");
  
  if($OSNAME =~ /aix/i)
  {
    $LDAPServer=getFromThere($GSACONF,"^cellname\\s*(.*)\$");
    if($LDAPServer eq "")
    {
      $LDAPServer=getFromThere($GSACONF,"^ldaphost\\s*\\S*,\\s*(.*)\$");
    }
  }  
  
  if($OSNAME =~ /linux/i)
  {
    $LDAPServer=getFromThere($LDAPCONF, "^host\\s*(.*)\$");
    if($LDAPServer eq "")
    {
      $LDAPServer=getFromThere($GSACONF, "^host\\s*(.*)\$");
    }
  }  
  logDebug("GSALDAP: LDAP server address is $LDAPServer");
  return $LDAPServer;
}

sub getLDAPBASE
{
  my $gsabase="";
  logDebug("getLDAPBASE: start");
  $gsabase=getFromThere($GSACONF, "^ldapbase\\s*(.*)\$");
  if($gsabase ne "")
  {
    $PEOPLEBASE="ou=People,$gsabase";
    $GROUPBASE="ou=Group,$gsabase";
  }
  if($OSNAME =~ /linux/i && $gsabase eq "")
  {
    $PEOPLEBASE=getFromThere($LDAPCONF, "^nss_base_passwd\\s*(.*)\\?");
    $GROUPBASE=getFromThere($LDAPCONF, "^nss_base_group\\s*(.*)\\?");
  }
  logDebug("getLDAPBASE:$PEOPLEBASE,$GROUPBASE");
}

sub extractSudoUsersGroups
{
  my $tmp_sudo_file="/tmp/sudoersfile.tmp";
  `rm -f $tmp_sudo_file`;
  
  %BLOCKED = ();
  my %sudousers=();
  &preparsesudoers($SUDOERS, $tmp_sudo_file);

  open SUDOERS_FILE, $tmp_sudo_file || logMsg(WARN, "Can't open SUDOERS:$tmp_sudo_file : $!\nAccount SUDO privileges will be missing from extract");
  while ($nextline = <SUDOERS_FILE>)
  {
    chomp($nextline);
    logDebug("extractSudoUsersGroups:read $nextline");
    chomp $nextline;
    ## concatenate line with next line if line ends with \
    if ( $nextline =~ /\\\s*$/ )
    {
      # process continuation line
      ($nline)=$nextline=~/(.*)\\\s*$/;
      chomp($nline);
      chop($nextline);
      $InputLine .= $nline;
      next;
    }
    $InputLine .= $nextline;

    ## trim out comment lines
    $cmt_ix = index( $InputLine, "#" );
    if ( $cmt_ix >= 0 )
    {
      $InputLine = substr( $InputLine, 0, $cmt_ix);
    }

    # split line into tokens (names and keywords)
    @Line = split /[,=\s]/, $InputLine;
    $ix = 0;

    # classify pieces of the input
    TOKEN: while ( $ix <= $#Line ) {
      if ( $Line[$ix] eq "" ) {  # ignore seperators
        $ix++;
        next TOKEN;
      }
      if ( $Line[$ix] eq "Cmnd_Alias" ){
        last TOKEN;
      }
      if ( $Line[$ix] eq "Runas_Alias" ){
        last TOKEN;
      }
      if ( $Line[$ix] eq "Defaults" ){
        last TOKEN;
      }
      if ( $Line[$ix] eq "Host_Alias" ){
        ($hostalias,$hostlist)=$InputLine=~/\s*\w+\s+(\w+)\s*\=\s*(.+)/;
        $hostlist =~ s/\s//g;
      
        foreach $nextHost (split ',', $hostlist) {
          $nextHost=glob2pat($nextHost);
          if ( $HOST =~ /$nextHost/i || $LONG_HOST_NAME =~ /$nextHost/i || "ALL" =~ /$nextHost/i)
          {
            $validHostAlias{$hostalias}=$hostalias;
          }
        }
        last TOKEN;
      }
      if ( $Line[$ix] eq "User_Alias" )
      {
        ($useralias,$aliaslist)=$InputLine=~/\s*\w+\s+(\w+)\s*\=\s*(.+)/;
        $aliaslist =~ s/\s//g;

        logDebug("extractSudoUsersGroups: $InputLine");
        logDebug("extractSudoUsersGroups: Found user_alias $useralias");
        logDebug("extractSudoUsersGroups: Found aliaslist $aliaslist");
        
        $AliasList{$useralias} = $aliaslist;
                    
        foreach $usr (split ',', $aliaslist)
        {
            logDebug("Added user $usr");
            $sudousers{$usr}=1;
        }  
        last TOKEN;
      }
      ($userlist,$hostlist)=$InputLine=~/\s*([\w\,\%\+\@\/\s]+\w)\s+([\,\!\w\s]+)\s*\=/;
      $userlist =~ s/\s//g;
      $hostlist =~ s/\s//g;
      $PROCESSLINE=0;
      if($priv =~ /!ALL/ )
      {
        logDebug("extractSudoUsersGroups: found !ALL");
        foreach $nextHost (split ',', $hostlist)
        {
          $nextHost1=glob2pat($nextHost);
          if ( $HOST =~ /$nextHost1/i || $LONG_HOST_NAME =~ /$nextHost1/i)
          {
            $PROCESSLINE=1;
          }
          elsif ("ALL" =~ /$nextHost1/i)
          {
            $PROCESSLINE=1;
          }
          elsif ($validHostAlias{$nextHost})
          {
            $PROCESSLINE=1;
          }
        }
        if($PROCESSLINE == 1)
        {
          if(exists($AliasList{$userlist}))
          {
            logDebug("extractSudoUsersGroups: $userlist is Alias");
            $userlist = $AliasList{$userlist};
            logDebug("extractSudoUsersGroups: corrected $userlist");
          }
      
          foreach my $usr (split ',', $userlist)
          {
            logDebug("extractSudoUsersGroups: added blocked user $usr");
            $BLOCKED{$usr}=1;
          }
          last TOKEN;
        }
      }
      foreach my $usr (split ',', $userlist)
      {
        $sudousers{$usr}=1;
        logDebug("extractSudoUsersGroups: added sudo user $usr");
      }
      last TOKEN;
    }
    $InputLine= "";
  } 

  close SUDOERS_FILE;
  `rm -f $tmp_sudo_file`;
  
  for my $gsauid (keys %sudousers)
  {
    if(exists($BLOCKED{$gsauid}))
    {
      logDebug("extractSudoUsersGroups: $gsauid is blocked, skipped");
      delete($MEMBERS{$gsauid});  
      next;
    }
    
    if(exists($AliasList{$gsauid}))
    {
      logDebug("extractSudoUsersGroups: $gsauid is Alias, skipped");
      next;
    }
    
    if($gsauid =~ /^%/ )
    {
      $gsauid =~ s/^%:*//;
      if($gsagrouplist ne "")
      {
        $gsagrouplist.=",$gsauid";
      }
      else
      {
       $gsagrouplist="$gsauid";
      }
      next;
    }
    logDebug("extractSudoUsersGroups:$gsauid is added to memberlist ");
    $MEMBERS{$gsauid}=1;
  }
  
  while(($key, $value) = each %AliasList){
    delete($AliasList{$key});
  };
  
  while(($key, $value) = each %BLOCKED){
    delete($BLOCKED{$key});
  };
  
  while(($key, $value) = each %sudousers){
    delete($sudousers{$key});
  };
}

sub getGSAgroup
{
  my @grouplist = split(',',shift);
  
  logDebug("getGSAgroup: starting");
      
  open LDAP_GROUP_FILE, ">$LDAPGROUP" || logAbort("Can't open $LDAPGROUP for writing : $!");
  foreach my $gsagroup (@grouplist)
  {
    logDebug("getGSAgroup: get gsagroup $gsagroup information");
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $GROUPBASE cn=$gsagroup cn gidNumber memberUid`;
    if ( $? != 0 )
    {
      close LDAP_GROUP_FILE;
      logAbort("6accessing LDAP server ($?)");
    }
    
    my $gidNumber="";
    my $memberUid="";
    
    foreach $line (split(/\n/,$attr))
    {
      logDebug("getGSAgroup: line=$line");
      if( $line =~ /^gidNumber:\s(\S+)/ )
      {
        $gidNumber = $1;
        logDebug("getGSAgroup: gidNumber=$gidNumber");
        next;
      }
      if( $line =~ /^memberUid:\s(\S+)/ )
      {
        $MEMBERS{$1}=1;
        if($memberUid ne "")
        {
          $memberUid.=",$1";
        }
        else
        {
          $memberUid="$1";
        }
        logDebug("getGSAgroup: memberUid=$1");
        next;
      }
    }
    print LDAP_GROUP_FILE "$gsagroup:!:$gidNumber:$memberUid\n";
    logDebug("getGSAgroup:groupfile->$gsagroup:!:$gidNumber:$memberUid");
  }   
  close LDAP_GROUP_FILE;
}

sub getGroupGID
{
  my $group = shift;
  
  logDebug("getGroupGID: group is $group");  
  
  my $temp=`$LDAPCMD -LLL -h $LDAPSVR -b $GROUPBASE cn="$group" gidNumber`;
  if ( $? != 0 )
  {
    logAbort("7accessing LDAP server ($?)");
  }
  foreach my $str (split(/\n/,$temp))
  {
    logDebug("getGroupGID:$str");
    if( $str =~ /^gidNumber:\s(\S+)/)
    {
      return $1;
    }
  }
  return "";
}

sub getAdditionalGroup
{
  open LDAP_GROUP_FILE, ">>$LDAPGROUP" || logAbort("Can't open $LDAPGROUP for append : $!");
  for my $gsauid (keys %MEMBERS)
  {
    logDebug("getAdditionalGroup: uid=$gsauid");
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $GROUPBASE memberUid=$gsauid cn`;
    if ( $? != 0 )
    {
      logAbort("8accessing LDAP server ($?)");
    }
    foreach $line (split(/\n/,$attr))
    {
      logDebug("getAdditionalGroup:$line");
      if( $line =~ /^cn:\s(\S+)/)
      {
        my $gsagroup = $1;
        my $gidNumber=getGroupGID($gsagroup);
        print LDAP_GROUP_FILE "$gsagroup:!:$gidNumber:$gsauid\n";
        next;
      }
    }
  }
  close LDAP_GROUP_FILE;
}

sub getGSAuser
{
  logDebug("getGSAuser: starting");  
  
  open LDAP_PASSWD_FILE, ">$LDAPPASSWD" || logAbort("Can't open $LDAPPASSWD for writing : $!");
  for my $gsauid (keys %MEMBERS)
  {
    logDebug("getGSAuser: gsauid=$gsauid");
    $attr=`$LDAPCMD -LLL -h $LDAPSVR -b $PEOPLEBASE uid=$gsauid uniqueIdentifier cn`;
    if ( $? != 0 )
    {
      close LDAP_PASSWD_FILE;
      logAbort("9accessing LDAP server ($?)");
    }
    
    my $uniqueIdentifier="";
    my $cn="";
    
    foreach $line (split(/\n/,$attr))
    {
      logDebug("getGSAuser: line=$line");
      if( $line =~ /^uniqueIdentifier:\s(\S+)/ )
      {
        $uniqueIdentifier=$1;
        logDebug("getGSAuser: uniqueIdentifier=$uniqueIdentifier");
        next;
      }
      if( $line =~ /^cn:\s(.+)/ )
      {
        $cn=$1;
        logDebug("getGSAuser: cn=$cn");
        next;
      }
    }
    
    if($uniqueIdentifier eq "" )
    {
      next;
    }
    
    my $CC=substr($uniqueIdentifier,6,3);
    my $SN=substr($uniqueIdentifier,0,6);
    
    my $IDs="";
    if($DEV == 1)
    {
      $IDs=`./id -u $gsauid`;
      $IDs=trim($IDs);
    }
    else
    {
      $IDs=`id -u $gsauid`;
      $IDs=trim($IDs);
    }
    
    my $GROUPID="";
    if($DEV == 1)
    {
      $GROUPID=`./id -g $gsauid`;
      $GROUPID=trim($GROUPID);
    }
    else
    {
      $GROUPID=`id -g $gsauid`;
      $GROUPID=trim($GROUPID);
    }
    
    print LDAP_PASSWD_FILE "$gsauid:!:$IDs:$GROUPID:$CC/K/$SN/IBM/$cn-GSA::\n";
    logDebug("getGSAuser:passwd->$gsauid:!:$IDs:$GROUPID:$CC/K/$SN/IBM/$cn-GSA::");
  }
  close LDAP_PASSWD_FILE;
}

sub collectGSAusers
{
  %MEMBERS = ();
  $gsagrouplist="";
  $GROUPBASE="";
  $PEOPLEBASE="";
    
  logDebug("collectGSAusers: started");
   
  $LDAPSVR = GSALDAP();
  
  if($LDAPSVR eq "")
  {
	  logInfo("LDAP server details not provided");
    #logAbort("LDAP server address not found");
  }
  
  getLDAPBASE();
  
  $gsagrouplist=getFromThere($GSACONF, "^gsagroupallow\\s*(.*)\$");
  if($OSNAME =~ /linux/i && $gsagrouplist eq "")
  {
    $gsagrouplist=getFromThere($LDAPCONF, "^gsagroupallow\\s*(.*)\$");
  }
  
  if($gsagrouplist eq "")
  {
    extractSudoUsersGroups();
  }
  
  if($gsagrouplist eq "")
  {
    logAbort("Can't get GSA group list");  
  }
  
  getGSAgroup($gsagrouplist);
  getGSAuser();
  
  if($gsagrouplist ne "")
  {
    getAdditionalGroup; 
  }
  
  logDebug("collectGSAusers: finished");
  while(($key, $value) = each %MEMBERS){
    delete($MEMBERS{$key});
  };
}

sub Report_UAT
{
  my $IsMaster = 0;
  my $serveraddr = "";
  my $outstr = "";
  
  if($DEV == 1)
  {
    $serveraddr = `./ypwhich 2>/dev/null`;
  }
  else
  {
    $serveraddr = `ypwhich 2>/dev/null`;
  }
  if ( $? == 0)
  {
    $serveraddr = trim($serveraddr);
    if($serveraddr eq "")
    {
      logMsg(WARN,"NIS server address is empty");
      return "";
    }
    logDebug("Report_UAT: found NIS serveraddr $serveraddr");
    $IsMaster = CompareAddr($serveraddr);
    if($IsMaster == 1)
    {
      $outstr = 'NIS_MASTER_SERVER';
    }
    else
    {
      $outstr = 'NIS_MEMBER_SERVER:'.$serveraddr;
    }
    logDebug("Report_UAT: return string $outstr");
    return $outstr;
  }
  elsif($OSNAME =~ /solaris/i || $OSNAME =~ /sunos/i)
  {
    my $out = "";
    if($DEV == 1)
    {
      $out = `./ldapclient list 2>/dev/null`;
    }
    else
    {
      $out = `ldapclient list 2>/dev/null`;
    }
    
    if ( $? != 0 )
    {
      logMsg(WARN,"Error reading LDAP info");
      return "";
    }
    foreach $line (split(/\n/,$out))
    {
      if( $line =~ /^NS_LDAP_SERVERS=(.*)/)
      {
        $serveraddr = trim($1);
        logDebug("Report_UAT: serveraddr $serveraddr");
        $IsMaster = CompareAddr($serveraddr);
        last;
      }
    }
  }
  elsif($OSNAME =~ /linux/i)
  {
    if($DEV == 1)
    {
      $serveraddr = getFromThere("./ldap.conf","^URI\\s*(.*)\$" );
    }
    else
    {
      $serveraddr = getFromThere("/etc/openldap/ldap.conf","^\\s*URI\\s*(.*)\$" );
    }
    
    if($serveraddr ne "")
    {
      $serveraddr =~ s/ldap:\/\//,/ig;
      $serveraddr =~ s/^,//;
      logDebug("Report_UAT: serveraddr $serveraddr");
      $IsMaster = CompareAddr($serveraddr);
    }
    else
    {
      logMsg(WARN,"No LDAP server address in ldap.conf");
      return "";
    }
  }elsif($OSNAME =~ /aix/i)
  {
    my $out ="";
    if($DEV == 1)
    {
      $out = `./ls-secldapclntd 2>/dev/null`;
    }
    else
    {
      $out = `ls-secldapclntd 2>/dev/null`;
    }
    
    if ( $? != 0 )
    {
      logMsg(WARN,"Error reading LDAP info");
      return "";
    }
    
    foreach $line (split(/\n/,$out)) 
    {
      if( $line =~ /^ldapservers=(.*)/)
      {
        $serveraddr = trim($1);
        logDebug("Report_UAT: serveraddr $serveraddr");
        last;
      }
    }
    my $serveraddr2 = "";
    if( $DEV ==1 )
    {
      $serveraddr2 =getFromThere("./ldap.cfg","^ldapservers:\\s*(.*)" );
    }
    else
    {
      $serveraddr2 =getFromThere("/etc/security/ldap/ldap.cfg","^\\s*ldapservers:\\s*(.*)" );
    }
    if($serveraddr2 eq "")
    {
      logMsg(WARN,"No LDAP server address in ldap.cfg");
      return "";
    }
    $serveraddr.=",".$serveraddr2;
    
    logDebug("Report_UAT: serveraddr $serveraddr");
    $IsMaster = CompareAddr($serveraddr);
  }
  
  if($IsMaster == 1)
  {
    $outstr = "LDAP_MASTER_SERVER";
  }
  elsif($serveraddr ne "" )
  {
    $outstr = "LDAP_MEMBER_SERVER:".$serveraddr;
  }
  logDebug("Report_UAT: return string $outstr");
  return $outstr;
}
sub CompareAddr
{
  my $cfg_addr = lc shift;
  my $local_addr = "";
  
  logDebug("CompareAddr: cfg_addr $cfg_addr");
  
  ($local_addr,@_)= split(/\./,$LONG_HOST_NAME);
  $local_addr.=",".$LONG_HOST_NAME;
  $local_addr.=",127.0.0.1,localhost";
  
  foreach $IP (split(/\n/,`ifconfig -a`))
  {
    if($IP =~ /\s*inet\s+(addr:)?\s*(\S+)\s+/)
    {
      if($2 ne "127.0.0.1")
      {
        $local_addr.=",".$2;
        logDebug("CompareAddr: local address $2");
      }
    }
  }
  logDebug("CompareAddr: local addr $local_addr");    
  foreach $cfg_a (split(/,/,$cfg_addr))
  {
    $cfg_a = lc trim($cfg_a);
    $cfg_a =~ s/\///g;
    
    foreach $local_a (split(/,/,$local_addr))
    {
      if(($local_a ne "" )&& ($local_a eq $cfg_a))
      {
        logDebug("CompareAddr: found local addr $local_a, config addr $cfg_a");
        return 1;
      }
    }
  }
  logDebug("CompareAddr: not found local addr $local_addr, config addr $cfg_addr");
  return 0;
}
sub GetGroupsforKerb {
        $KerbGrp="";
        `realm list > $KERBCONF`;
	open GRP, $KERBCONF;
        while ($line = <GRP>)
        {
       		logDebug("GRP each line:$line");
                next if($line =~ /^#/);
                if($line =~ /^\s*permitted-groups:(.+)/) {
                        $KerbGrp=$1;
                        @KerbGrps=split(/,/,$KerbGrp);
       			logDebug("all groups:@KerbGrps");
                        foreach (@KerbGrps) {
                                $KerbGrp1=(split(/@/,$_))[0];
                                push(@Kgroups,$KerbGrp1);
                        }
                }
		if($line =~ /^\s*permitted-logins:(.+)/) {
       			logDebug("Permitted users:$1");
                        @Pusers=split(/,/,$1);
		}
		
        }
	close(GRP);
}

sub GetGroupsforKerb1 {
        $KerbGrp="";
        open GRP, $KERBCONF;
        while ($line = <GRP>)
        {
                next if($line =~ /^#/);
                if($line =~ /^\+:\((.+)\):/) {
                        $KerbGrp=$1;
                        push(@Kgroups,$KerbGrp);
                }
        }
}
sub GetOracleUnifiedDirUsersAndGroups {
	`ldapsearch -h $OULDSVR -p $OULDPORT -D "cn=Directory Manager" -w $LDAPPWD -b "$OULDBASE" -s one "(uid=*)" uid cn sn description > $Otmpfile`;
	
    logDebug("LDAP COmmand: ldapsearch -h $OULDSVR -p $OULDPORT -D cn=Directory Manager -w $LDAPPWD -b $OULDBASE -s one (uid=*) uid cn sn description");
	
	open OULD_FILE, "$Otmpfile" || logAbort("Can't open $Otmpfile for writing : $!");
  
	my $CNEnable=0;
	my $GEnable =0;
	my $total_lines=`wc -l $Otmpfile | awk '{print $1}'`;
	chomp($total_lines);
	my $line_count =0;
	while ($line=<OULD_FILE>)
	{
		print "==========each line OULD:$line\n";
		$line_count++;
		
		if ($line =~ /^uid:\s(\S+)/ )
		{
			$UName =  $1;
			push(@LUNames,$UName);
			$CNEnable=1;
			next;
		}
		if ($line =~ /^description:\s(.+)/ )
		{
			$desc =  $1;
			next;
		}
		 if($CNEnable ==1) {
			$OULD_USER_LIST{USER_DESC}->{$UName}=$desc;
			print "description:$OULD_USER_LIST{USER_DESC}->{$UName}";
		}

		if ($line =~ /^isMemberOf:\scn=(\w+),ou/i)
		{
			$GName= $1;
			$GEnable = 1;
			push(@LGroups,$GName);
			push(@AllLGroups,$GName);
			if($total_lines == $line_count) {
				my %hash   = map { $_, 1 } @LGroups;
				my @unique_groups = keys %hash;
				$JoinAllGroups=join(",",@unique_groups);
				$OULD_USER_LIST{USER_GROUPS}->{$UName}=$JoinAllGroups;
				$CNEnable=0;
				$GEnable =0;
				#$OULD_USER_LIST{USER_DESC}->{$UName}=$desc;
				print "--------------$UName=======$OULD_USER_LIST{USER_DESC}->{$UName}=========$OULD_USER_LIST{USER_GROUPS}->{$UName}\n";
				@LGroups = ();
			}
			next;
		}
		if($CNEnable ==1 && $GEnable ==1 && $line =~ /^dn.*/) {
			my %hash   = map { $_, 1 } @LGroups;
			my @unique_groups = keys %hash;
			$JoinAllGroups=join(",",@unique_groups);
			$OULD_USER_LIST{USER_GROUPS}->{$UName}=$JoinAllGroups;
			$CNEnable=0;
			$GEnable =0;
			print "--------------$UName=======$OULD_USER_LIST{USER_DESC}->{$UName}=========$OULD_USER_LIST{USER_GROUPS}->{$UName}\n";
			@LGroups = ();
		}
	}
	my %hash1   = map { $_, 1 } @AllLGroups;
	@AllLGroups = keys %hash1;
}
sub GetPermittedUsersAndGroups {
	foreach $Euser (@Pusers) {
		$Euser=~ s/^\s//;
		$Euser=~ s/\s$//;
                push(@KerbMem,$Euser);
       		logDebug(" permitted each usre :$Euser");
		$PermGroups=`groups $Euser | sed 's/^.*: //'`;
       		logDebug("groups for permitted usres :$PermGroups");
                $KerbUserIDData{$Euser}{KGRP}=$PermGroups;
	}
}

sub GetKerbMembers {
        foreach $KGrp (@Kgroups) {
        logDebug("Processing each group:$KGrp");
		$KGrp=~ s/^\s//;
                `ldapsearch -LLL -H "ldap://$KERBSVR" -b $KERBBASE cn=$KGrp cn member gidNumber > $Ktmpfile`;
                logDebug("ldapsearch -LLL -H ldap://$KERBSVR -b $KERBBASE cn=$KGrp cn member gidNumber");
                open GRP_FILE, "$Ktmpfile";
                while (<GRP_FILE>) {
                logDebug("processing each line for kerb groups:$_");
                        if (/^member:\sCN=([a-zA-Z0-9\s-_+*&%#@]+),/ ) {
                                $Kerb_Uid=$1;
        			logDebug("Group:$KGrp,User : $Kerb_Uid");
                                push(@KerbMem,$Kerb_Uid);
                                if(exists $KerbUserIDData{$Kerb_Uid}{KGRP})
                                {
                                        $KerbUserIDData{$Kerb_Uid}{KGRP} = $KerbUserIDData{$Kerb_Uid}{KGRP}.",$KGrp";
                                } else {
                                        $KerbUserIDData{$Kerb_Uid}{KGRP}=$KGrp;
                                }
                        }
                }
                close(GRP_FILE);
        }

}

sub GetKerbIDDesc {
        my $Kerb_user = shift;
	$KFuid=$Kerb_user;
        $gecos="";
        $userstate="";
	$uid="";

        `ldapsearch -LLL -H "ldap://$KERBSVR" -b $KERBBASE cn="$Kerb_user" uid userpassword uidNumber gidNumber loginShell gecos host description userAccountControl sAMAccountName > $Ktmpfile1`;
        logDebug("ldapsearch -LLL -H ldap://$KERBSVR -b $KERBBASE cn=$Kerb_user uid userpassword uidNumber gidNumber loginShell gecos host description userAccountControl sAMAccountName > $Ktmpfile1");
        open DESC_FILE, "$Ktmpfile1";
        while ($line = <DESC_FILE>) {
        logDebug("processing each line for Desc:$line");
                if ( $line =~ /^gecos:\s(.+)$/ && $gecos eq "") {
                        $gecos = $1;
                        next;
                }
                if ( $line =~ /^description:\s(.+)$/ ) {
                        $gecos = $1;
                        next;
                }
		if ( $line =~ /^userAccountControl:\s(.+)$/ ) {
                        $userAccCont = $1;
                        if( $userAccCont =~ /512/ ) {
                                $userstate = "Enabled";
                        } elsif ( $userAccCont =~ /514/ ) {
                                $userstate = "Disabled";
                        }
                        next;
                }
                if ( $line =~ /^sAMAccountName:\s(.+)$/ ) {
                        $uid = $1;
                        next;
                }
        }
        close(DESC_FILE);
	if($uid eq "") {
        	logDebug("Shortname is empty for user $Kerb_user");
		$uid=$Kerb_user;	
	}
        $KerbIDInfo = "$KFuid:$uid:$userstate:$gecos";
        return $KerbIDInfo;

}


