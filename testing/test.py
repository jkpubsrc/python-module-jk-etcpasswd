#!/usr/bin/python3








import jk_etcpasswd




#
# If testing is enabled the objects will verify that the data reproduced after parsing will match the actual content of the files.
#
# Please note that these classes will order the groups a user is assigned to. If the order in the credential files is not alphabetical an error will
# occure as then the output generated will not match the input.
#
# As this test feature is only ment to verify correctness of the implementation and not ment to be used in real world scenarios no more
# sophisticated test logic has been implemented.
#

pwdFiles = jk_etcpasswd.PwdFile(bTest = True)
grpFiles = jk_etcpasswd.GrpFile(bTest = True)













