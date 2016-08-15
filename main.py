import runner
import sys
import argparse

parser = argparse.ArgumentParser(description='Run a webapp for Google Safe list checker.')
parser.add_argument('--debug', dest='debug', default=False, action='store_true', help='enable debug mode')
parser.add_argument('--debug-port', dest='debugPort', nargs='?', type=int, default=3000, help='debugger port. default: 3000')
parser.add_argument('--debug-secret', dest='debugSecret', nargs='?', type=str, default="debugstuff", help='debugger secret. default "debugstuff"')

try:
    args = vars(parser.parse_args())
except:
    parser.print_help()
    sys.exit(0)

# Start
if __name__ == "__main__":
    if args['debug'] is True:
        import ptvsd
        print "Starter remote debugger on port: " + str(args['debugPort'])
        ptvsd.enable_attach(args['debugSecret'], address = ('0.0.0.0', args['debugPort']))

    runner.runApp()