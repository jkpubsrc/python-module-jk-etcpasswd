

import os
import sys
import codecs
import typing

import jk_typing


from .PwdRecord import PwdRecord





class PwdFile(object):

	@jk_typing.checkFunctionSignature()
	def __init__(self, pwdFile:str = "/etc/passwd", shadowFile:str = "/etc/shadow", bTest:bool = False):
		self.__pwdFile = pwdFile
		self.__shadowFile = shadowFile

		self.__records = []
		self.__recordsByUserName = {}

		with codecs.open(pwdFile, "r", "utf-8") as f:
			sPwdFile = f.read()

		lineNo = -1
		for line in sPwdFile.split("\n"):
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

		with codecs.open(shadowFile, "r", "utf-8") as f:
			sShadowFile = f.read()

		lineNo = -1
		for line in sShadowFile.split("\n"):
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
				pwdFileContent = sPwdFile,
				shadowFileContent = sShadowFile,
			)
	#

	#
	# This method verifies that the data stored in this object reproduces the exact content of the password files in "/etc".
	# An exception is raised on error.
	#
	@jk_typing.checkFunctionSignature()
	def _compareDataTo(self, pwdFile:str = None, shadowFile:str = None, pwdFileContent:str = None, shadowFileContent:str = None):
		if pwdFileContent is None:
			if pwdFile is None:
				pwdFile = self.__pwdFile
			with codecs.open(pwdFile, "r", "utf-8") as f:
				pwdFileContent = f.read()

		if shadowFileContent is None:
			if shadowFile is None:
				shadowFile = self.__shadowFile
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
	# Write the stored content to the password files in "/etc".
	#
	@jk_typing.checkFunctionSignature()
	def store(self, pwdFile:str = None, shadowFile:str = None):
		if pwdFile is None:
			pwdFile = self.__pwdFile
		if shadowFile is None:
			shadowFile = self.__shadowFile

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

	def get(self, userNameOrID:typing.Union[str,int]) -> PwdRecord:
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










