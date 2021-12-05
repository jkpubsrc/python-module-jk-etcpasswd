

import os
import sys
import codecs
import typing

import jk_typing


from .PwdRecord import PwdRecord





class PwdFile(object):

	@jk_typing.checkFunctionSignature()
	def __init__(self, pwdFile:str = "/etc/passwd", shadowFile:str = "/etc/shadow", pwdFileContent:str = None, shadowFileContent:str = None, bTest:bool = False, jsonData:dict = None):
		self.__records = []					# stores PwdRecord objects
		self.__recordsByUserName = {}		# stores str->PwdRecord

		if jsonData is None:
			# regular instantiation

			self.__pwdFilePath = pwdFile
			self.__shadowFilePath = shadowFile

			if pwdFileContent is None:
				with codecs.open(pwdFile, "r", "utf-8") as f:
					pwdFileContent = f.read()

			if shadowFileContent is None:
				with codecs.open(shadowFile, "r", "utf-8") as f:
					shadowFileContent = f.read()

			lineNo = -1
			for line in pwdFileContent.split("\n"):
				lineNo += 1
				if not line:
					continue

				line = line.rstrip("\n")
				items = line.split(":")
				if (len(items) != 7) or (items[1] != 'x'):
					raise Exception("Line " + str(lineNo + 1) + ": Invalid file format: " + pwdFile)
				r = PwdRecord(items[0], int(items[2]), int(items[3]), items[4], items[5], items[6])
				self.__records.append(r)
				self.__recordsByUserName[r.userName] = r

			lineNo = -1
			for line in shadowFileContent.split("\n"):
				lineNo += 1
				if not line:
					continue

				line = line.rstrip("\n")
				items = line.split(":")
				if len(items) != 9:
					raise Exception("Line " + str(lineNo + 1) + ": Invalid file format: " + shadowFile)
				r = self.__recordsByUserName.get(items[0])
				if r is None:
					raise Exception("Line " + str(lineNo + 1) + ": User \"" + items[0] + "\" not found! Invalid file format: " + shadowFile)
				r.secretPwdHash = items[1]
				r.extraShadowData = items[2:]

			# ----

			if bTest:
				self._compareDataTo(
					pwdFile = pwdFile,
					shadowFile = shadowFile,
					pwdFileContent = pwdFileContent,
					shadowFileContent = shadowFileContent,
				)

		else:
			# deserialization

			assert jsonData["pwdFormat"] == 1

			self.__pwdFilePath = jsonData["pwdFilePath"]
			self.__shadowFilePath = jsonData["pwdShadowFilePath"]

			for jRecord in jsonData["pwdRecords"]:
				r = PwdRecord.createFromJSON(jRecord)
				self.__records.append(r)
				self.__recordsByUserName[r.userName] = r
	#

	def toJSON(self) -> dict:
		ret = {
			"pwdFormat": 1,
			"pwdFilePath": self.__pwdFilePath,
			"pwdShadowFilePath": self.__shadowFilePath,
			"pwdRecords": [ r.toJSON() for r in self.__records ],
		}
		return ret
	#

	def idToNameMap(self) -> typing.Dict[int,str]:
		ret = {}
		for r in self.__records:
			ret[r.userID] = r.userName
		return ret
	#

	def nameToIDMap(self) -> typing.Dict[str,int]:
		ret = {}
		for r in self.__records:
			ret[r.userName] = r.userID
		return ret
	#

	@staticmethod
	def createFromJSON(j:dict):
		assert isinstance(j, dict)
		return PwdFile(jsonData=j)
	#

	#
	# This method verifies that the data stored in this object reproduces the exact content of the password files in "/etc".
	# An exception is raised on error.
	#
	@jk_typing.checkFunctionSignature()
	def _compareDataTo(self, pwdFile:str = None, shadowFile:str = None, pwdFileContent:str = None, shadowFileContent:str = None):
		if pwdFileContent is None:
			if pwdFile is None:
				pwdFile = self.__pwdFilePath
			with codecs.open(pwdFile, "r", "utf-8") as f:
				pwdFileContent = f.read()

		if shadowFileContent is None:
			if shadowFile is None:
				shadowFile = self.__shadowFilePath
			with codecs.open(shadowFile, "r", "utf-8") as f:
				shadowFileContent = f.read()

		contentPwdFile, contentShadowFile = self.toStringLists()

		lineNo = -1
		for line in pwdFileContent.split("\n"):
			lineNo += 1
			if not line:
				continue

			line = line.rstrip("\n")
			if line != contentPwdFile[lineNo]:
				print("--      Line read: " + repr(line))
				print("-- Line generated: " + repr(contentPwdFile[lineNo]))
				raise Exception("Line " + str(lineNo + 1) + ": Lines differ in file: " + pwdFile)

		lineNo = -1
		for line in shadowFileContent.split("\n"):
			lineNo += 1
			if not line:
				continue

			line = line.rstrip("\n")
			if line != contentShadowFile[lineNo]:
				print("--      Line read: " + repr(line))
				print("-- Line generated: " + repr(contentShadowFile[lineNo]))
				raise Exception("Line " + str(lineNo + 1) + ": Lines differ in file: " + shadowFile)
	#

	#
	# Write the content to the password files in "/etc".
	#
	@jk_typing.checkFunctionSignature()
	def store(self, pwdFile:str = None, shadowFile:str = None):
		if pwdFile is None:
			pwdFile = self.__pwdFilePath
		if shadowFile is None:
			shadowFile = self.__shadowFilePath

		contentPwdFile, contentShadowFile = self.toStrings()

		with codecs.open(pwdFile, "w", "utf-8") as f:
			os.fchmod(f.fileno(), 0o644)
			f.write(contentPwdFile)

		with codecs.open(shadowFile, "w", "utf-8") as f:
			os.fchmod(f.fileno(), 0o640)
			f.write(contentShadowFile)
	#

	def toStrings(self) -> typing.Tuple[str,str]:
		contentPwdFile = ""
		contentShadowFile = ""

		for r in self.__records:
			contentPwdFile += r.userName + ":x:" + str(r.userID) + ":" + str(r.groupID) + ":" + r.description + ":" + r.homeDirPath + ":" + r.shellDirPath + "\n"
			contentShadowFile += r.userName + ":" + r.secretPwdHash + ":" + ":".join(r.extraShadowData) + "\n"

		return contentPwdFile, contentShadowFile
	#

	def toStringLists(self) -> typing.Tuple[list,list]:
		contentPwdFile = []
		contentShadowFile = []

		for r in self.__records:
			contentPwdFile.append(r.userName + ":x:" + str(r.userID) + ":" + str(r.groupID) + ":" + r.description + ":" + r.homeDirPath + ":" + r.shellDirPath)
			contentShadowFile.append(r.userName + ":" + r.secretPwdHash + ":" + ":".join(r.extraShadowData))

		return contentPwdFile, contentShadowFile
	#

	def get(self, userNameOrID:typing.Union[str,int]) -> typing.Union[PwdRecord,None]:
		if isinstance(userNameOrID, str):
			return self.__recordsByUserName.get(userNameOrID, None)
		elif isinstance(userNameOrID, int):
			for r in self.__records:
				if r.userID == userNameOrID:
					return r
			return None
		else:
			raise Exception("Invalid data specified for argument 'userNameOrID': " + repr(userNameOrID))
	#

#










