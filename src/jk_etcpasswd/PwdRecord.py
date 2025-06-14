

import typing

import jk_prettyprintobj



class PwdRecord(jk_prettyprintobj.DumpMixin):

	__slots__ = (
		"userName",
		"userID",
		"groupID",
		"description",
		"homeDirPath",
		"shellDirPath",
		"secretPwdHash",
		"extraShadowData",
	)

	################################################################
	## Constants
	################################################################

	################################################################
	## Constructor
	################################################################

	def __init__(self, userName:str, userID:int, groupID:int, description:str, homeDirPath:str, shellDirPath:str):
		assert isinstance(userName, str)
		assert isinstance(userID, int)
		assert isinstance(groupID, int)
		assert isinstance(description, str)
		assert isinstance(homeDirPath, str)
		assert isinstance(shellDirPath, str)

		self.userName = userName
		self.userID = userID
		self.groupID = groupID
		self.description = description
		self.homeDirPath = homeDirPath
		self.shellDirPath = shellDirPath
		self.secretPwdHash:typing.Union[str,None] = None
		self.extraShadowData:typing.Union[str,None] = None
	#

	################################################################
	## Properties
	################################################################

	################################################################
	## Helper Methods
	################################################################

	def _dumpVarNames(self) -> typing.List[str]:
		return [
			"userName",
			"userID",
			"groupID",
			"description",
			"homeDirPath",
			"shellDirPath",
			"secretPwdHash",
			"extraShadowData",
		]
	#

	################################################################
	## Public Methods
	################################################################

	def toJSON(self) -> dict:
		ret = {
			"userName": self.userName,
			"userID": self.userID,
			"groupID": self.groupID,
			"description": self.description,
			"homeDirPath": self.homeDirPath,
			"shellDirPath": self.shellDirPath,
			"secretPwdHash": self.secretPwdHash,
			"extraShadowData": self.extraShadowData,
		}
		return ret
	#

	################################################################
	## Public Static Methods
	################################################################

	@staticmethod
	def createFromJSON(j:dict):
		assert isinstance(j, dict)
		ret = PwdRecord(j["userName"], j["userID"], j["groupID"], j["description"], j["homeDirPath"], j["shellDirPath"]) 
		ret.secretPwdHash = j["secretPwdHash"]
		ret.extraShadowData = j["extraShadowData"]
		return ret
	#

#










