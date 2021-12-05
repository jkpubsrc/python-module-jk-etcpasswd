

import os
import sys
import codecs
import typing

#import jk_typing



class GrpRecord(object):

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

	def __init__(self, groupName:str, groupID:int, extraGroups:list):
		assert isinstance(groupName, str)
		assert isinstance(groupID, int)
		assert isinstance(extraGroups, list)

		self.groupName = groupName
		self.groupID = groupID
		self.extraGroups = extraGroups
		self.groupPassword = None
	#

	################################################################
	## Properties
	################################################################

	################################################################
	## Helper Methods
	################################################################

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










