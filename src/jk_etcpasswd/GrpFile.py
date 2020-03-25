

import collections
import os
import sys
import codecs
import typing

import jk_typing


from .GrpRecord import GrpRecord





class GrpFile(object):

	def __init__(self, pwdFile = "/etc/group", shadowFile = "/etc/gshadow", bTest:bool = False):
		self.__pwdFile = pwdFile
		self.__shadowFile = shadowFile

		self.__records = []
		self.__recordsByGroupName = {}

		with codecs.open(pwdFile, "r", "utf-8") as f:
			sPwdFile = f.read()

		lineNo = -1
		for line in sPwdFile.split("\n"):
			lineNo += 1
			if not line:
				continue

			line = line.rstrip("\n")
			items = line.split(":")
			if (len(items) != 4) or (items[1] != 'x'):
				raise Exception("Line " + str(lineNo + 1) + ": Invalid file format: " + pwdFile)
			extraGroups = self.__parseExtraGroups(items[3])
			r = GrpRecord(items[0], int(items[2]), extraGroups)
			self.__records.append(r)
			self.__recordsByGroupName[r.groupName] = r

		with codecs.open(shadowFile, "r", "utf-8") as f:
			sShadowFile = f.read()

		lineNo = -1
		for line in sShadowFile.split("\n"):
			lineNo += 1
			if not line:
				continue

			line = line.rstrip("\n")
			items = line.split(":")
			if (len(items) != 4) or (len(items[2]) > 0):
				raise Exception("Line " + str(lineNo + 1) + ": Invalid file format: " + shadowFile)
			r = self.__recordsByGroupName.get(items[0])
			if r is None:
				raise Exception("Line " + str(lineNo + 1) + ": User \"" + items[0] + "\" not found! Invalid file format: " + shadowFile)
			r.groupPassword = items[1]
			extraGroups = self.__parseExtraGroups(items[3])
			r.extraGroups.union(extraGroups)

		# ----

		if bTest:
			self._compareDataTo(
				pwdFile = pwdFile,
				shadowFile = shadowFile,
				pwdFileContent = sPwdFile,
				shadowFileContent = sShadowFile,
			)
	#

	def __parseExtraGroups(self, groupString:typing.Union[str,None]) -> set:
		if (groupString is None) or (len(groupString.strip()) == 0):
			return set()
		else:
			return set(groupString.split(","))
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
			contentPwdFile += r.groupName + ":x:" + str(r.groupID) + ":" + ",".join(sorted(r.extraGroups)) + "\n"
			contentShadowFile += r.groupName + ":" + r.groupPassword + "::" + ",".join(sorted(r.extraGroups)) + "\n"

		return contentPwdFile, contentShadowFile
	#

	def toStringLists(self) -> typing.Tuple[list,list]:
		contentPwdFile = []
		contentShadowFile = []

		for r in self.__records:
			contentPwdFile.append(r.groupName + ":x:" + str(r.groupID) + ":" + ",".join(r.extraGroups))
			contentShadowFile.append(r.groupName + ":" + r.groupPassword + "::" + ",".join(r.extraGroups))

		return contentPwdFile, contentShadowFile
	#

	def get(self, groupNameOrID:typing.Union[str,int]) -> GrpRecord:
		if isinstance(groupNameOrID, str):
			return self.__recordsByGroupName.get(groupNameOrID, None)
		elif isinstance(groupNameOrID, int):
			for r in self.__records:
				if r.groupID == groupNameOrID:
					return r
			return None
		else:
			raise Exception("Invalid data specified for argument 'groupNameOrID': " + repr(groupNameOrID))
	#

#










