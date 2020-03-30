#!/usr/bin/python3








import jk_etcpasswd

import jk_json



#
# If testing is enabled the objects will verify that the data reproduced from parsed data right after parsing matches the actual content of the files.
#
# Please note that these classes will order the groups a user is assigned to. If the order in the credential files is not alphabetical an error will
# occure as then the output generated will not match the input.
#
# As this test feature is only ment to verify correctness of the implementation and not ment to be used in real world scenarios no more
# sophisticated test logic has been implemented.
#

bTest = False

pwdFile1 = jk_etcpasswd.PwdFile(bTest = bTest)
grpFile1 = jk_etcpasswd.GrpFile(bTest = bTest)


jPwdFile1 = pwdFile1.toJSON()
sPwdFile1 = jk_json.dumps(jPwdFile1, indent="\t", sort_keys=True)

jGrpFile1 = grpFile1.toJSON()
sGrpFile1 = jk_json.dumps(jGrpFile1, indent="\t", sort_keys=True)

grpFile2 = jk_etcpasswd.GrpFile.createFromJSON(jGrpFile1)
pwdFile2 = jk_etcpasswd.PwdFile.createFromJSON(jPwdFile1)

sPwdFile2 = jk_json.dumps(pwdFile2.toJSON(), indent="\t", sort_keys=True)
sGrpFile2 = jk_json.dumps(grpFile2.toJSON(), indent="\t", sort_keys=True)

assert sPwdFile1 == sPwdFile2
assert sGrpFile1 == sGrpFile2










