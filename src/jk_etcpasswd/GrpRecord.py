

import os
import sys
import codecs
import typing

import jk_typing



class GrpRecord(object):

	@jk_typing.checkFunctionSignature()
	def __init__(self, groupName:str, groupID:int, extraGroups:set):
		self.groupName = groupName
		self.groupID = groupID
		self.extraGroups = extraGroups
		self.groupPassword = None
	#

#










