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
			result = self.run_case(case)
			self.caseinfo[key].update(result)
		return self.caseinfo

	def run_case(self,case_dict):
		if case_dict['expected_result'] not in ['', 'N/A']:
			if '|' not in case_dict['expected_result']:
				expcted_result = case_dict['expected_result']
				command = case_dict['case_command']
				msg = re.compile(r'%s'%expcted_result)
				out,err = self.process(command)
				if os.path.isfile(os.path.join(self.mould_file_path,case_dict['expected_result'])):
					if out ==  self.read_module_txt_file(os.path.join(self.mould_file_path,case_dict['expected_result'])):
						case_dict['case_result'] = 'Pass'
	#					print case_dict['case_id']
					else:
						case_dict['case_result'] = 'Fail'
				else:
					if err:
						if msg.search(err):
							case_dict['case_result'] = 'Pass'
	#		    			print case_dict['case_id']
						else:
							print "%s fail message not match expected_result"%case_dict['case_id']
							case_dict['case_result'] = 'Fail'
			else:
				result = False
				expcted_result = case_dict['expected_result'].split('|')[-1]
				command, value = self.parser_command(case_dict['case_command'])
				print case_dict['case_id']
				if '-o' in value.keys():
					if os.path.exists(os.path.join(self.generatecapsule_path,value['-o'])):
						os.remove(value['-o'])
					run_out, run_err = self.process(command)
					if run_err:
						OUT = run_err
						result = False
					else:
						info_out,info_err = self.process('%s --dump-info'%value['-o'])
						OUT =(run_out+run_err+info_out+info_err).replace(' ','')
						for v in value.keys():
							if v in ['--capflag','--capoemflag','--guid','--hardware-instance','--monotonic-count','--version','--lsv','--debug']:
								if v == '--guid':
									tmp = self._search_info(self.command_dict[v], OUT, value[v].upper())
								elif v == '--capflag':
									tmp = self._search_info(self.command_dict[v], OUT)
								else:
									tmp = self._search_info(self.command_dict[v],OUT,'%08X'%eval(value[v]))
								result = tmp & True
					if result == True:
						case_dict['case_result'] = 'Pass'
					else:
						print "%s fail message: %s" % (case_dict['case_id'],OUT)
						case_dict['case_result'] = 'Fail'
		else:
			pass
		#	print "%s not have expected result" % (case_dict['case_id'])
		return case_dict

	def _search_info(self,name,content,value=None):
		if value == None:
			reg = re.compile(r'%s'%name)
			if reg.search(content):
				return True
			else:
				return False
		else:
			reg = re.compile(r'%s=%s'%(name,value))
			if reg.search(content):
				return True
			else:
				return False

	def read_module_txt_file(self,file):
		with open(file,'r') as mf:
			read= mf.read()
		return read

	def parser_command(self,command):
		_command_with_arg = ['-o','--capflag','--capoemflag','--guid','--hardware-instance','--monotonic-count','--version','--lsv','--pfx-file','--signer-private-cert','--other-public-cert','--trusted-public-cert','--signing-tool-path','--debug']
		_command_without_arg = ['-h','-e','-d','--dump-info','-v','-q']
		#print command
		dict = {}
		tmp =[]
		c_list = command.split(' ')
		for c in c_list:
			if c in _command_with_arg:
				dict[c] = c_list[c_list.index(c)+1]
				tmp.append(c)
				tmp.append(c_list[c_list.index(c)+1])
		other =[elem for elem in c_list if elem not in tmp and elem !='']
		#print other
		#print dict
		return command,dict

	def process(self,command):
		try:
			result = subprocess.Popen('python %s %s' % (self.script_path, command),stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			out = result.stdout.read()
			err = result.stderr.read()
			return out,err
		except Exception,e:
			print e

class write_result(config):

	def __init__(self):
		super(write_result, self).__init__()
		self.report = openpyxl.load_workbook(self.report_file)
		active = self.report.active
		self.sheet = self.report[active.title]

	def color(self,value):
		if value == "Fail":
			return styles.Font(color=styles.colors.RED)
		elif value == "Pass":
			return styles.Font(color=styles.colors.GREEN)
		else:
			return

	def result_to_excel(self,dict):
		for title in self.sheet[1]:
			if title.value == 'ID':
				ID_col = title.column
			elif title.value == 'Result':
				Rst_col = title.column
			else:
				ID_col = 'G'
				Rst_col = "H"
		for n in range(2,self.sheet.max_row+1):
			if self.sheet['%s%d'%(ID_col,n)].value:
				if self.sheet['%s%d'%(ID_col,n)].value == dict['case_id']:
					self.sheet['%s%d' % (Rst_col, n)].value = dict['case_result']
					self.sheet['%s%d' % (Rst_col, n)].font = self.color(self.sheet['%s%d' % (Rst_col, n)].value)

	def save(self):
		return self.report.save('test.xlsx')

def main():
	case = create_case()
	write_test_result = write_result()
	os.environ['PYTHONPATH'] = case.python_path
	print 'Please select case to run:\n'
	print '1. Run all test case\n'
	print '2. Run test case by case %s\n'%case.excel_info[(0,0)]
	print '3. Run test case by case %s\n'%case.excel_info[(0,1)]
	print '4. Run test case by case %s\n'%case.excel_info[(0,5)]
	input = int(raw_input())
	if input == 1:
		print "Run all"
		result = case.all_case()
		for i in result.keys():
			write_test_result.result_to_excel(result[i])
		write_test_result.save()
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
