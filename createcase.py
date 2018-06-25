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
import openpyxl
import openpyxl.styles as styles

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
		self.generatecapsule_path = parse.get('PATH','GenerateCapsule_path').strip('"')
		self.script_name =parse.get('PATH','Script_name').strip('"')
		self.cert_file_path = parse.get('PATH','Cert_file_path').strip('"')
		self.signing_tool_path = parse.get('PATH','Signing_tool_path').strip('"')
		self.mould_file_path = parse.get('PATH','Mould_file_path').strip('"')
		self.script_path = os.path.join(self.generatecapsule_path,self.script_name)
		self.python_path = parse.get('PATH','PYTHON_PATH').strip('"')
		self.report_file = parse.get('PATH','Report_file').strip('"')

	def test(self):
		pass

class create_case(config):

	def __init__(self):
		super(create_case,self).__init__()
		self.case_sheet = "GenerateCapsule"
		self.excel_info = self.read_excel()
		self.caseinfo = self.case_info()
		self.flag_dict ={
			'PersistAcrossReset' : {'CAPSULE_FLAGS_PERSIST_ACROSS_RESET':0x00010000},
			'PopulateSystemTable': {'CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE':0x00020000},
			'InitiateReset'      : {'CAPSULE_FLAGS_INITIATE_RESET':0x00040000},
		}
		self.command_dict ={
			'-h'                         : '',
			'-o'                         : '',
			'-e'                         : '',
			'-d'                         : '',
			'--dump-info'                : '',
			'--capflag'                  : 'EFI_CAPSULE_HEADER.Flags',
			'--capoemflag'               : 'OEM Flags',
			'--guid'                     : 'EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER.UpdateImageTypeId',
			'--hardware-instance'        : 'EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER.UpdateHardwareInstance',
			'--monotonic-count'          : 'EFI_FIRMWARE_IMAGE_AUTHENTICATION.MonotonicCount',
			'--version'                  : 'FMP_PAYLOAD_HEADER.FwVersion',
			'--lsv'                      : 'FMP_PAYLOAD_HEADER.LowestSupportedVersion',
			'--pfx-file'                 : '',
			'--signer-private-cert'      : '',
			'--other-public-cert'        : '',
			'--trusted-public-cert'      : '',
			'--signing-tool-path'        : '',
			'-v'                         : '',
			'-q'                         : '',
			'--debug'                    : ''
		}

	def read_excel(self):
		info={}
		try:
			excel = xlrd.open_workbook(self.report_file)
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
		return info

	def case_info(self):
		case = {}
		title ={}
		for i in self.excel_info.keys():
			if i[0] == 0:
				title[self.excel_info[i]] = i[1]
		for i in self.excel_info.keys():
			tmp={}
			tmp['case_location'] = (i[0],title['ID'])
			tmp['case_calssify'] = self.excel_info[i[0], 0] + '_' + self.excel_info[i[0], 1]
			if self.excel_info[i[0],2] == self.excel_info[i[0],3]:
				tmp['case_name'] = self.excel_info[i[0],0]+'_'+self.excel_info[i[0],1]+'_'+self.excel_info[i[0],2]
			else:
				tmp['case_name'] = self.excel_info[i[0], 0] + '_' + self.excel_info[i[0], 1] + '_' + self.excel_info[i[0], 2]+'_'+self.excel_info[i[0],3]
			tmp['case_command'] = self.excel_info[i[0],title['Command']]
			tmp['case_id'] = self.excel_info[i[0], title['ID']]
			tmp['case_result'] = self.excel_info[i[0], title['Result']]
			tmp['expected_result'] = self.excel_info[i[0], title['Expected result']]
			case[(i[0],title['ID'])]=tmp
		for key in case.keys():
			if case[key]['case_id'] in ['','ID']:
				del case[key]
	#	for i in case.keys():
	#		print case[i]
		return case

	def all_case(self):
		for key in self.caseinfo.keys():
			case = self.caseinfo[key]
			self.run_case(case)

	def run_case(self,case_dict):
		msg = re.compile(r'%s'%case_dict['expected_result'])
		try:
			if case_dict['expected_result'] not in ['','N/A']:
				result = subprocess.Popen('python %s %s' % (self.script_path, case_dict['case_command']),
				                          stdout=subprocess.PIPE,stderr=subprocess.PIPE)
				out = result.stdout.read()
				err = result.stderr.read()
				if os.path.isfile(os.path.join(self.mould_file_path,case_dict['expected_result'])):
					if out ==  self.read_module(os.path.join(self.mould_file_path,case_dict['expected_result'])):
						case_dict['case_result'] = 'PASS'
						print case_dict['case_id']
					else:
						case_dict['case_result'] = 'Fail'
				else:
					if err:
						if msg.search(err):
							case_dict['case_result'] = 'PASS'
							print case_dict['case_id']
						else:
							print "%s fail message not match expected_result"%case_dict['case_id']
							case_dict['case_result'] = 'Fail'
			else:
				print "%s not have expected result"%(case_dict['case_id'])
			return case_dict
		except Exception,e:
			print e

	def read_module(self,file):
		with open(file,'r') as mf:
			read= mf.read()
		return read

class write_result(object):

	def __init__(self):
		pass

	def result_to_excel(self):
		pass

def main():
	case = create_case()
	os.environ['PYTHONPATH'] = case.python_path
	print 'Please select case to run:\n'
	print '1. Run all test case\n'
	print '2. Run test case by case %s\n'%case.excel_info[(0,0)]
	print '3. Run test case by case %s\n'%case.excel_info[(0,1)]
	print '4. Run test case by case %s\n'%case.excel_info[(0,5)]
	input = int(raw_input())
	if input == 1:
		print "Run all"
		case.all_case()
	elif input == 2:
		print "Category"
	elif input == 3:
		print "Item"
	elif input == 4:
		print "Please input case %s"%case.excel_info[(0,5)]
	else:
		sys.exit(1)


if __name__ == "__main__":
	main()
	#case = create_case()

	#case.case_info()
	#os.environ['PYTHONPATH'] = case.python_path
	#dict= {'case_result': '', 'case_calssify': 'Basic_Function', 'case_location': (4, 6), 'case_name': 'Basic_Function_\
	#  -o   _GenerateCapsule.py -o', 'case_id': 'TC-4', 'expected_result': 'GenerateCapsule: error: argument -o/--output: expected one argument', 'case_command': ' -o'}
	#case.run_case(dict)
