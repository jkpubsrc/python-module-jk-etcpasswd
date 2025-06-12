

import typing

import jk_prettyprintobj



class GrpRecord(jk_prettyprintobj.DumpMixin):

	__slots__ = (
		"groupName",
		"groupID",
		"extraGroups",
		"groupPassword",
	)

	################################################################
	## Constants
	################################################################

	################################################################
	## Constructor
	################################################################

	def __init__(self, groupName:str, groupID:int, extraGroups:typing.List[str]):
		assert isinstance(groupName, str)
		assert isinstance(groupID, int)
		assert isinstance(extraGroups, list)

		self.groupName = groupName
		self.groupID = groupID
		self.extraGroups = extraGroups
		self.groupPassword:typing.Union[str,None] = None
	#

	################################################################
	## Properties
	################################################################

	################################################################
	## Helper Methods
	################################################################

	def _dumpVarNames(self) -> typing.List[str]:
		return [
			"groupName",
			"groupID",
			"extraGroups",
			"groupPassword",
		]
	#

	################################################################
	## Public Methods
	################################################################

	def toJSON(self) -> dict:
		ret = {
			"groupName": self.groupName,
			"groupID": self.groupID,
			"extraGroups": self.extraGroups,
			"groupPassword": self.groupPassword,
		}
		return ret
	#

	################################################################
	## Public Static Methods
	################################################################

	@staticmethod
	def createFromJSON(j:dict):
		assert isinstance(j, dict)
		ret = GrpRecord(j["groupName"], j["groupID"], j["extraGroups"]) 
		ret.groupPassword = j["groupPassword"]
		return ret
	#

#










