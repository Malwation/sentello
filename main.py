from components.caller import caller
import optparse


def get_input():
    parse_ob.add_option("-t", "--tls", dest="tls", action="store_true",
                        default=False, help="enable tls controls")
    parse_ob.add_option("-d", "--debug", dest="debug", action="store_true",
                        default=False,  help="enable debug controls")
    parse_ob.add_option("-i", "--injection", dest="injection",
                        action="store_true", default=False,  help="enable injection controls")
    parse_ob.add_option("-s", "--sandbox", dest="sandbox",
                        action="store_true", default=False,  help="enable sandbox controls")
    parse_ob.add_option("-v", "--vbox", dest="vbox", action="store_true",
                        default=False,  help="enable vbox controls")
    parse_ob.add_option("-V", "--vmware", dest="vmware",
                        action="store_true", help="enable vmware controls")
    parse_ob.add_option("-p", "--vpc", dest="vpc", action="store_true",
                        default=False,  help="enable virtual pc controls")
    parse_ob.add_option("-q", "--qemu", dest="qemu", action="store_true",
                        default=False,  help="enable qemu controls")
    parse_ob.add_option("-x", "--xen", dest="xen", action="store_true",
                        default=False,  help="enable xen controls")
    parse_ob.add_option("-w", "--wine", dest="wine", action="store_true",
                        default=False, help="enable wine controls")
    parse_ob.add_option("-P", "--parallels", dest="parallels",
                        action="store_true", default=False,  help="enable parallels controls")
    parse_ob.add_option("-c", "--code-injection", dest="code", action="store_true",
                        default=False,  help="enable code injections controls")
    parse_ob.add_option("-T", "--timing", dest="timing", action="store_true",
                        default=False,  help="enable time based controls")
    parse_ob.add_option("-D", "--dumping", dest="dumping",
                        action="store_true", default=False,  help="enable dumping controls")
    parse_ob.add_option("-Y", "--tools", dest="tools", action="store_true",
                        default=False,  help="enable tools controls")
    parse_ob.add_option("-a", "--disasm", dest="disasm",
                        action="store_true", default=False, help="enable disasm controls")
    parse_ob.add_option("-A", "--all", dest="all", action="store_true",
                        default=False, help="enable all controls")


if __name__ == "__main__":
    usage = "usage: %prog [options] arg1 arg2"
    parse_ob = optparse.OptionParser(usage=usage)
    get_input()
    user, a = parse_ob.parse_args()
    requests = vars(user)
    if not True in list(requests.values()):
        print(parse_ob.print_help())
    else:
        if requests["all"] == True:
            del requests["all"]
            for i in requests:
                if "all" != i:
                    requests[i] = True
        print("Sentello Started")
        caller(requests)
        print("Sentello Ended")
        print("logs:output.json")
