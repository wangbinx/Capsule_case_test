#!/usr/bin/python
#This script for GenerateCapsule case test
##
import xlrd
import re
import os
import sys
import shutil
import subprocess
import ConfigParser
from optparse import OptionParser

class config(object):

	def __init__(self):
		root = os.getcwd()
		self.config_file = os.path.join(root,'config.cnf')
	#	self.basetool_path = ''
	#	self.generatecapsule_path =''
	#	self.cert_file_path = ''
	#	self.signing_tool_path =''
	#	self.mould_file_path =''

#	def configure(self):
		parse=ConfigParser.ConfigParser()
		parse.read(self.config_file)
		self.basetool_path = parse.get('PATH','BaseTools_path').strip('"')
		self.generatecapsule_path = parse.get('PATH','GenerateCapsule_path').strip('"')
		self.cert_file_path = parse.get('PATH','Cert_file_path').strip('"')
		self.signing_tool_path = parse.get('PATH','Signing_tool_path').strip('"')
		self.mould_file_path = parse.get('PATH','Mould_file_path').strip('"')

	def test(self):
		pass


class create_case(config):

	def __init__(self):
		super(create_case,self).__init__()
		root = os.getcwd()
		self.excel_file = os.path.join(root,'GenerateCapsule.xlsx')
		self.case_sheet = "GenerateCapsule"
		self.excel_info = self.read_excel()

	def read_excel(self):
		info={}
		try:
			excel = xlrd.open_workbook(self.excel_file)
			sheet = excel.sheet_by_name(self.case_sheet)
		except Exception,e:
			print "Open Excel file error:%s" %e
			sys.exit(1)
		col = sheet.ncols
		row = sheet.nrows
		for r in range(0,row):
			for c in range(0,col):
				info[(r,c)] = sheet.cell_value(r,c).encode('utf-8')
		for cell in  sheet.merged_cells:
			rlo, rhi, clo, chi = cell
			value = ''
			for rowx in range(rlo, rhi):
				for colx in range(clo, chi):
					if sheet.cell_value(rowx,colx):
						value = sheet.cell_value(rowx,colx)
					info[(rowx,colx)]=value.encode('utf-8')
	#	for i in info.keys():
	#		print i,info[i]
		return info

	def case_info(self):
		case = []
		title ={}
		for i in self.excel_info.keys():
			if i[0] == 0:
				title[self.excel_info[i]] = i[1]
		for i in self.excel_info.keys():
			tmp={}
	#		tmp['case_location'] = (i[0],title['ID'])
			tmp['case_calssify'] = self.excel_info[i[0], 0] + '_' + self.excel_info[i[0], 1]
			if self.excel_info[i[0],2] == self.excel_info[i[0],3]:
				tmp['case_name'] = self.excel_info[i[0],0]+'_'+self.excel_info[i[0],1]+'_'+self.excel_info[i[0],2]
			else:
				tmp['case_name'] = self.excel_info[i[0], 0] + '_' + self.excel_info[i[0], 1] + '_' + self.excel_info[i[0], 2]+'_'+self.excel_info[i[0],3]
			tmp['case_command'] = self.excel_info[i[0],title['command']]
			tmp['case_number'] = self.excel_info[i[0], title['ID']]
			tmp['case_result'] = self.excel_info[i[0], title['Result']]
			tmp['expected result'] = self.excel_info[i[0], title['expected result']]
			case.append(tmp)
		for j in case:
			print j
		return case

	def run_case(self,case_dict):
		subprocess.check_call('GenerateCapsule.py')



def main():
	case = create_case()
	print 'Please select case to run:\n'
	print '1. Run all test case\n'
	print '2. Run test case by case %s\n'%case.excel_info[(0,0)]
	print '3. Run test case by case %s\n'%case.excel_info[(0,1)]
	print '4. Run test case by case %s\n'%case.excel_info[(0,5)]
	input = int(raw_input())
	if input == 1:
		print "Run all"
	elif input == 2:
		print "Category"
	elif input == 3:
		print "Item"
	elif input == 4:
		print "Please input case %s"%case.excel_info[(0,5)]
	else:
		sys.exit(1)


if __name__ == "__main__":
	#main()
	case = create_case()
	case.case_info()
	co = config()
	print case.config_file
	print case.basetool_path
	print co.generatecapsule_path
	print co.cert_file_path
	print co.signing_tool_path
	print co.mould_file_path