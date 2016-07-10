import webapp

# Start
if __name__ == "__main__":
    try:
        webapp.googleproc.start()
        webapp.app.run(host="0.0.0.0")
    except KeyboardInterrupt:
        print "Interrupt received, stopping..."
    finally:
        # clean up
        print "Closing the resources."
        webapp.googleproc.stop()
        webapp.googleproc.waitforclose()
        webapp.tstore.close()
        