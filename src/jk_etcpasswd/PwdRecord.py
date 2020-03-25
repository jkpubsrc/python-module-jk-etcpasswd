

import os
import sys
import codecs
import typing

import jk_typing



class PwdRecord(object):

	@jk_typing.checkFunctionSignature()
	def __init__(self, userName:str, userID:int, groupID:int, description:str, homeDirPath:str, shellDirPath:str):
		self.userName = userName
		self.userID = userID
		self.groupID = groupID
		self.description = description
		self.homeDirPath = homeDirPath
		self.shellDirPath = shellDirPath
		self.secretPwdHash = None
		self.extraShadowData = None
	#

#










