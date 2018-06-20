## @file
# Generate a capsule.
#
# Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
# This program and the accompanying materials
# are licensed and made available under the terms and conditions of the BSD License
# which accompanies this distribution.  The full text of the license may be found at
# http://opensource.org/licenses/bsd-license.php
#
# THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
# WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
#

'''
GenerateCapsule
'''

import sys
import argparse
import uuid
import struct
import subprocess
import os
import tempfile
import shutil
from Common.Uefi.Capsule.UefiCapsuleHeader import UefiCapsuleHeaderClass
from Common.Uefi.Capsule.FmpCapsuleHeader  import FmpCapsuleHeaderClass
from Common.Uefi.Capsule.FmpAuthHeader     import FmpAuthHeaderClass
from Common.Edk2.Capsule.FmpPayloadHeader  import FmpPayloadHeaderClass

#
# Globals for help information
#
__prog__        = 'GenerateCapsule'
__copyright__   = 'Copyright (c) 2018, Intel Corporation. All rights reserved.'
__description__ = 'Generate a capsule.\n'

def SignPayloadSignTool (Payload, ToolPath, PfxFile):
    #
    # Create a temporary directory
    #
    TempDirectoryName = tempfile.mkdtemp()

    #
    # Generate temp file name for the payload contents
    #
    TempFileName = os.path.join (TempDirectoryName, 'Payload.bin')

    #
    # Create temporary payload file for signing
    #
    try:
        File = open (TempFileName, mode='wb')
        File.write (Payload)
        File.close ()
    except:
        shutil.rmtree (TempDirectoryName)
        raise ValueError ('GenerateCapsule: error: can not write temporary payload file.')

    #
    # Build signtool command
    #
    if ToolPath is None:
        ToolPath = ''
    Command = ''
    Command = Command + '"{Path}" '.format (Path = os.path.join (ToolPath, 'signtool.exe'))
    Command = Command + 'sign /fd sha256 /p7ce DetachedSignedData /p7co 1.2.840.113549.1.7.2 '
    Command = Command + '/p7 {TempDir} '.format (TempDir = TempDirectoryName)
    Command = Command + '/f {PfxFile} '.format (PfxFile = PfxFile)
    Command = Command + TempFileName
    print "Command: %s" %Command
    #
    # Sign the input file using the specified private key
    #
    try:
        Process = subprocess.Popen (Command, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
        Result = Process.communicate('')
    except:
        shutil.rmtree (TempDirectoryName)
        raise ValueError ('GenerateCapsule: error: can not run signtool.')

    if Process.returncode != 0:
        shutil.rmtree (TempDirectoryName)
        print (Result[1].decode())
        raise ValueError ('GenerateCapsule: error: signtool failed.')

    #
    # Read the signature from the generated output file
    #
    try:
        File = open (TempFileName + '.p7', mode='rb')
        Signature = File.read ()
        File.close ()
    except:
        shutil.rmtree (TempDirectoryName)
        raise ValueError ('GenerateCapsule: error: can not read signature file.')

    shutil.rmtree (TempDirectoryName)
    return Signature

def VerifyPayloadSignTool (Payload, CertData, ToolPath, PfxFile):
    print ('signtool verify is not supported.')
    raise ValueError ('GenerateCapsule: error: signtool verify is not supported.')

def SignPayloadOpenSsl (Payload, ToolPath, SignerPrivateCertFile, OtherPublicCertFile, TrustedPublicCertFile):
    #
    # Build openssl command
    #
    if ToolPath is None:
        ToolPath = ''
    Command = ''
    Command = Command + '"{Path}" '.format (Path = os.path.join (ToolPath, 'openssl'))
    Command = Command + 'smime -sign -binary -outform DER -md sha256 '
    Command = Command + '-signer "{Private}" -certfile "{Public}" -purpose any'.format (Private = SignerPrivateCertFile, Public = OtherPublicCertFile)
    print "Command: %s"%Command
    #
    # Sign the input file using the specified private key and capture signature from STDOUT
    #
    try:
        Process = subprocess.Popen (Command, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
        Result = Process.communicate(input = Payload)
        Signature = Result[0]
    except:
        raise ValueError ('GenerateCapsule: error: can not run openssl.')

    if Process.returncode != 0:
        print (Result[1].decode())
        raise ValueError ('GenerateCapsule: error: openssl failed.')

    return Signature

def VerifyPayloadOpenSsl (Payload, CertData, ToolPath, SignerPrivateCertFile, OtherPublicCertFile, TrustedPublicCertFile):
    #
    # Create a temporary directory
    #
    TempDirectoryName = tempfile.mkdtemp()

    #
    # Generate temp file name for the payload contents
    #
    TempFileName = os.path.join (TempDirectoryName, 'Payload.bin')

    #
    # Create temporary payload file for verification
    #
    try:
        File = open (TempFileName, mode='wb')
        File.write (Payload)
        File.close ()
    except:
        shutil.rmtree (TempDirectoryName)
        raise ValueError ('GenerateCapsule: error: can not write temporary payload file.')

    #
    # Build openssl command
    #
    if ToolPath is None:
        ToolPath = ''
    Command = ''
    Command = Command + '"{Path}" '.format (Path = os.path.join (ToolPath, 'openssl'))
    Command = Command + 'smime -verify -inform DER '
    Command = Command + '-content {Content} -CAfile "{Public}" -purpose any'.format (Content = TempFileName, Public = TrustedPublicCertFile)
    print "Command: %s"%Command
    #
    # Verify signature
    #
    try:
        Process = subprocess.Popen (Command, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
        Result = Process.communicate(input = CertData)
    except:
        shutil.rmtree (TempDirectoryName)
        raise ValueError ('GenerateCapsule: error: can not run openssl.')

    if Process.returncode != 0:
        shutil.rmtree (TempDirectoryName)
        print (Result[1].decode())
        raise ValueError ('GenerateCapsule: error: openssl failed.')

    shutil.rmtree (TempDirectoryName)
    return Payload

if __name__ == '__main__':
    def convert_arg_line_to_args(arg_line):
        for arg in arg_line.split():
            if not arg.strip():
                continue
            yield arg

    def ValidateUnsignedInteger (Argument):
        try:
            Value = int (Argument, 0)
        except:
            Message = '{Argument} is not a valid integer value.'.format (Argument = Argument)
            raise argparse.ArgumentTypeError (Message)
        if Value < 0:
            Message = '{Argument} is a negative value.'.format (Argument = Argument)
            raise argparse.ArgumentTypeError (Message)
        return Value

    def ValidateRegistryFormatGuid (Argument):
        try:
            Value = uuid.UUID (Argument)
        except:
            Message = '{Argument} is not a valid registry format GUID value.'.format (Argument = Argument)
            raise argparse.ArgumentTypeError (Message)
        return Value

    #
    # Create command line argument parser object
    #
    parser = argparse.ArgumentParser (
                        prog = __prog__,
                        description = __description__ + __copyright__,
                        conflict_handler = 'resolve',
                        fromfile_prefix_chars = '@'
                        )
    parser.convert_arg_line_to_args = convert_arg_line_to_args

    #
    # Add input and output file arguments
    #
    parser.add_argument("InputFile",  type = argparse.FileType('rb'),
                        help = "Input binary payload filename.")
    parser.add_argument("-o", "--output", dest = 'OutputFile', type = argparse.FileType('wb'),
                        help = "Output filename.")
    #
    # Add group for -e and -d flags that are mutually exclusive and required
    #
    group = parser.add_mutually_exclusive_group (required = True)
    group.add_argument ("-e", "--encode", dest = 'Encode', action = "store_true",
                        help = "Encode file")
    group.add_argument ("-d", "--decode", dest = 'Decode', action = "store_true",
                        help = "Decode file")
    group.add_argument ("--dump-info", dest = 'DumpInfo', action = "store_true",
                        help = "Display FMP Payload Header information")
    #
    # Add optional arguments for this command
    #
    parser.add_argument ("--capflag", dest = 'CapsuleFlag', action='append', default = [],
                         choices=['PersistAcrossReset', 'PopulateSystemTable', 'InitiateReset'],
                         help = "Capsule flag can be PersistAcrossReset, or PopulateSystemTable or InitiateReset or not set")
    parser.add_argument ("--capoemflag", dest = 'CapsuleOemFlag', type = ValidateUnsignedInteger, default = 0x0000,
                         help = "Capsule OEM Flag is an integer between 0x0000 and 0xffff.")

    parser.add_argument ("--guid", dest = 'Guid', type = ValidateRegistryFormatGuid,
                         help = "The FMP/ESRT GUID in registry format.  Required for encode operations.")
    parser.add_argument ("--hardware-instance", dest = 'HardwareInstance', type = ValidateUnsignedInteger, default = 0x0000000000000000,
                         help = "The 64-bit hardware instance.  The default is 0x0000000000000000")


    parser.add_argument ("--monotonic-count", dest = 'MonotonicCount', type = ValidateUnsignedInteger, default = 0x0000000000000000,
                         help = "64-bit monotonic count value in header.  Default is 0x0000000000000000.")

    parser.add_argument ("--version", dest = 'FwVersion', type = ValidateUnsignedInteger,
                         help = "The 32-bit version of the binary payload (e.g. 0x11223344 or 5678).")
    parser.add_argument ("--lsv", dest = 'LowestSupportedVersion', type = ValidateUnsignedInteger,
                         help = "The 32-bit lowest supported version of the binary payload (e.g. 0x11223344 or 5678).")

    parser.add_argument ("--pfx-file", dest='SignToolPfxFile', type=argparse.FileType('rb'),
                         help="signtool PFX certificate filename.")

    parser.add_argument ("--signer-private-cert", dest='OpenSslSignerPrivateCertFile', type=argparse.FileType('rb'),
                         help="OpenSSL signer private certificate filename.")
    parser.add_argument ("--other-public-cert", dest='OpenSslOtherPublicCertFile', type=argparse.FileType('rb'),
                         help="OpenSSL other public certificate filename.")
    parser.add_argument ("--trusted-public-cert", dest='OpenSslTrustedPublicCertFile', type=argparse.FileType('rb'),
                         help="OpenSSL trusted public certificate filename.")

    parser.add_argument ("--signing-tool-path", dest = 'SigningToolPath',
                         help = "Path to signtool or Open SLL tool.  Optional if path to tools are already in PATH.")

    #
    # Add optional arguments common to all commands
    #
    parser.add_argument("-v", "--verbose", dest = 'Verbose', action = "store_true",
                        help = "Increase output messages")
    parser.add_argument("-q", "--quiet", dest = 'Quiet', action = "store_true",
                        help = "Reduce output messages")
    parser.add_argument("--debug", dest = 'Debug', type = int, metavar = '[0-9]', choices = range(0,10), default = 0,
                        help = "Set debug level")

    #
    # Parse command line arguments
    #
    args = parser.parse_args()

    #
    # Perform additional argument verification
    #
    if not args.DumpInfo and args.OutputFile is None:
        parser.error ('the following arguments are required for all commands except --dump-info: --output')

    if args.Encode and (args.Guid is None or args.FwVersion is None or args.LowestSupportedVersion is None):
        parser.error ('the following arguments are required: --version, --lsv, --guid')

    if not args.DumpInfo and not args.OutputFile:
        parser.error ('the following arguments are required: --output')

    if not args.DumpInfo:
        if args.SignToolPfxFile is None and args.OpenSslSignerPrivateCertFile is None and args.OpenSslOtherPublicCertFile is None and args.OpenSslTrustedPublicCertFile is None:
            parser.error ('certificate file arguments are required: --pfx-file | [--signer-private-cert --other-public-cert --trusted-public-cert]')

    if args.SignToolPfxFile is not None:
        if args.OpenSslSignerPrivateCertFile is not None:
            parser.error ('Providing both signtool and OpenSSL options is not supported')
        if args.OpenSslOtherPublicCertFile is not None:
            parser.error ('Providing both signtool and OpenSSL options is not supported')
        if args.OpenSslTrustedPublicCertFile is not None:
            parser.error ('Providing both signtool and OpenSSL options is not supported')
        args.SignToolPfxFile.close()
        args.SignToolPfxFile = args.SignToolPfxFile.name

    if not args.DumpInfo:
        if args.SignToolPfxFile is None:
            if args.OpenSslSignerPrivateCertFile is None:
                parser.error ('the following arguments are required: --signer-private-cert')
            if args.OpenSslOtherPublicCertFile is None:
                parser.error ('the following arguments are required: --other-public-cert')
            if args.OpenSslTrustedPublicCertFile is None:
                parser.error ('the following arguments are required: --trusted-public-cert')
            args.OpenSslSignerPrivateCertFile.close()
            args.OpenSslOtherPublicCertFile.close()
            args.OpenSslTrustedPublicCertFile.close()
            args.OpenSslSignerPrivateCertFile = args.OpenSslSignerPrivateCertFile.name
            args.OpenSslOtherPublicCertFile   = args.OpenSslOtherPublicCertFile.name
            args.OpenSslTrustedPublicCertFile = args.OpenSslTrustedPublicCertFile.name

    #
    # Read binary input file
    #
    try:
        if args.Verbose:
            print ('Read binary input file {File}'.format (File = args.InputFile.name))
        Buffer = args.InputFile.read ()
        args.InputFile.close ()
    except:
        print ('GenerateCapsule: error: can not read binary input file {File}'.format (File = args.InputFile.name))
        sys.exit (1)

    #
    # Create objects
    #
    UefiCapsuleHeader = UefiCapsuleHeaderClass ()
    FmpCapsuleHeader  = FmpCapsuleHeaderClass ()
    FmpAuthHeader     = FmpAuthHeaderClass ()
    FmpPayloadHeader  = FmpPayloadHeaderClass ()

    if args.Encode:
        try:
            FmpPayloadHeader.FwVersion              = args.FwVersion
            FmpPayloadHeader.LowestSupportedVersion = args.LowestSupportedVersion
            FmpPayloadHeader.Payload                = Buffer
            Result = FmpPayloadHeader.Encode ()
            if args.Verbose:
                FmpPayloadHeader.DumpInfo ()
        except:
            print ('GenerateCapsule: error: can not encode FMP Payload Header')
            sys.exit (1)

        #
        # Sign image with 64-bit MonotonicCount appended to end of image
        #
        str = struct.pack ('<Q', args.MonotonicCount)
        ustr= struct.unpack('<Q',str)
        print ustr,str
        try:
          if args.SignToolPfxFile is not None:
              CertData = SignPayloadSignTool (
                           Result + struct.pack ('<Q', args.MonotonicCount),
                           args.SigningToolPath,
                           args.SignToolPfxFile
                           )
          else:
              CertData = SignPayloadOpenSsl (
                           Result + struct.pack ('<Q', args.MonotonicCount),
                           args.SigningToolPath,
                           args.OpenSslSignerPrivateCertFile,
                           args.OpenSslOtherPublicCertFile,
                           args.OpenSslTrustedPublicCertFile
                           )
        except:
            print ('GenerateCapsule: error: can not sign payload')
            raise
            sys.exit (1)

        try:
            FmpAuthHeader.MonotonicCount = args.MonotonicCount
            FmpAuthHeader.CertData       = CertData
            FmpAuthHeader.Payload        = Result
            Result = FmpAuthHeader.Encode ()
            if args.Verbose:
                FmpAuthHeader.DumpInfo ()
        except:
            print ('GenerateCapsule: error: can not encode FMP Auth Header')
            sys.exit (1)

        try:
            FmpCapsuleHeader.AddPayload (args.Guid, Result, HardwareInstance = args.HardwareInstance)
            Result = FmpCapsuleHeader.Encode ()
            if args.Verbose:
                FmpCapsuleHeader.DumpInfo ()
        except:
            print ('GenerateCapsule: error: can not encode FMP Capsule Header')
            sys.exit (1)

        try:
            UefiCapsuleHeader.OemFlags            = args.CapsuleOemFlag
            UefiCapsuleHeader.PersistAcrossReset  = 'PersistAcrossReset'  in args.CapsuleFlag
            UefiCapsuleHeader.PopulateSystemTable = 'PopulateSystemTable' in args.CapsuleFlag
            UefiCapsuleHeader.InitiateReset       = 'InitiateReset'       in args.CapsuleFlag
            UefiCapsuleHeader.Payload             = Result
            Result = UefiCapsuleHeader.Encode ()
            if args.Verbose:
                UefiCapsuleHeader.DumpInfo ()
        except:
            print ('GenerateCapsule: error: can not encode UEFI Capsule Header')
            sys.exit (1)

    elif args.Decode:
        try:
            Result = UefiCapsuleHeader.Decode (Buffer)
            FmpCapsuleHeader.Decode (Result)
            Result = FmpCapsuleHeader.GetFmpCapsuleImageHeader (0).Payload
            Result = FmpAuthHeader.Decode (Result)

            #
            # Verify Image with 64-bit MonotonicCount appended to end of image
            #
            try:
              if args.SignToolPfxFile is not None:
                  CertData = VerifyPayloadSignTool (
                               FmpAuthHeader.Payload + struct.pack ('<Q', FmpAuthHeader.MonotonicCount),
                               FmpAuthHeader.CertData,
                               args.SigningToolPath,
                               args.SignToolPfxFile
                               )
              else:
                  CertData = VerifyPayloadOpenSsl (
                               FmpAuthHeader.Payload + struct.pack ('<Q', FmpAuthHeader.MonotonicCount),
                               FmpAuthHeader.CertData,
                               args.SigningToolPath,
                               args.OpenSslSignerPrivateCertFile,
                               args.OpenSslOtherPublicCertFile,
                               args.OpenSslTrustedPublicCertFile
                               )
            except ValueError:
                print ('GenerateCapsule: warning: can not verify payload.')

            Result = FmpPayloadHeader.Decode (Result)
            if args.Verbose:
                print ('========')
                UefiCapsuleHeader.DumpInfo ()
                print ('--------')
                FmpCapsuleHeader.DumpInfo ()
                print ('--------')
                FmpAuthHeader.DumpInfo ()
                print ('--------')
                FmpPayloadHeader.DumpInfo ()
                print ('========')
        except:
            print ('GenerateCapsule: error: can not decode capsule')
            raise
            sys.exit (1)

    elif args.DumpInfo:
        try:
            Result = UefiCapsuleHeader.Decode (Buffer)
            FmpCapsuleHeader.Decode (Result)
            Result = FmpCapsuleHeader.GetFmpCapsuleImageHeader (0).Payload
            Result = FmpAuthHeader.Decode (Result)
            Result = FmpPayloadHeader.Decode (Result)

            print ('========')
            UefiCapsuleHeader.DumpInfo ()
            print ('--------')
            FmpCapsuleHeader.DumpInfo ()
            print ('--------')
            FmpAuthHeader.DumpInfo ()
            print ('--------')
            FmpPayloadHeader.DumpInfo ()
            print ('========')
        except:
            print ('GenerateCapsule: error: can not decode capsule')
            sys.exit (1)
    else:
        print('GenerateCapsule: error: invalid options')
        sys.exit (1)

    #
    # Write binary output file
    #
    if args.OutputFile is not None:
        try:
            if args.Verbose:
                print ('Write binary output file {File}'.format (File = args.OutputFile.name))
            args.OutputFile.write (Result)
            args.OutputFile.close ()
        except:
            print ('GenerateCapsule: error: can not write binary output file {File}'.format (File = args.OutputFile.name))
            sys.exit (1)

    if args.Verbose:
        print('Success')
