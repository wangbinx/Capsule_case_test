#!/usr/bin/python
#This script for GenerateCapsule case test
##
import xlrd
import re
import os
import sys
import shutil
import subprocess
from optparse import OptionParser

class read_case_form_excel(object):

	def __init__(self):
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
				info[(r,c)] = sheet.cell_value(r,c)
		for cell in  sheet.merged_cells:
			rlo, rhi, clo, chi = cell
			value = ''
			for rowx in range(rlo, rhi):
				for colx in range(clo, chi):
					if sheet.cell_value(rowx,colx):
						value = sheet.cell_value(rowx,colx)
					info[(rowx,colx)]=value
	#	for i in info.keys():
	#		print i,info[i]
		return info

	def create_case(self):
		case = []
		for i in self.excel_info.keys():
			tmp={}
			tmp['case_location'] = (i[0],4)
			tmp['case_calssify'] = self.excel_info[i[0], 0] + '__' + self.excel_info[i[0], 1]
			if self.excel_info[i[0],2] == self.excel_info[i[0],3]:
				tmp['case_name'] = self.excel_info[i[0],0]+'_'+self.excel_info[i[0],1]+'_'+self.excel_info[i[0],2]
			else:
				tmp['case_name'] = self.excel_info[i[0], 0] + '_' + self.excel_info[i[0], 1] + '_' + self.excel_info[i[0], 2]+'_'+self.excel_info[i[0],3]
			tmp['case_command'] = self.excel_info[i[0],4]
			tmp['case_number'] = self.excel_info[i[0], 5]
			tmp['case_result'] = self.excel_info[i[0], 6]
			case.append(tmp)
	#		case_location = (i[0],4)
	#		if self.excel_info[i[0],2] == self.excel_info[i[0],3]:
	#			case_name = self.excel_info[i[0],0]+'_'+self.excel_info[i[0],1]+'_'+self.excel_info[i[0],2]
	#		else:
	#			case_name = self.excel_info[i[0], 0] + '_' + self.excel_info[i[0], 1] + '_' + self.excel_info[i[0], 2]+'_'+self.excel_info[i[0],3]
	#		case_command = self.excel_info[i[0],4]
	#		case_calssify = self.excel_info[i[0],0]+'__'+self.excel_info[i[0],1]
	#		#case.append((case_location,case_name,case_command,case_calssify))
	#	for j in case:
	#		print j
		return case

def main():
	read_excel = read_case_form_excel()
	print 'Please select case to run:\n'
	print '1. Run all test case\n'
	print '2. Run test case by case %s\n'%read_excel.excel_info[(0,0)]
	print '3. Run test case by case %s\n'%read_excel.excel_info[(0,1)]
	print '4. Run test case by case %s\n'%read_excel.excel_info[(0,5)]
	input = int(raw_input())
	if input == 1:
		print "Run all"
	elif input == 2:
		print "Category"
	elif input == 3:
		print "Item"
	elif input == 4:
		print "Please input case %s"%read_excel.excel_info[(0,5)]
	else:
		sys.exit(1)


if __name__ == "__main__":
	main()