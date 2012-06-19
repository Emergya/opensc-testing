OpenSC testing
==============

Set of tests for OpenDNIe and OpenSC projects

# opensc-testing-core #

* [Applet example](http://emergya.github.com/opensc-testing/)
* [Javadoc](http://emergya.github.com/opensc-testing/apidocs/index.html)

## Maven test ##

Run with:

<pre>~opensc-testing-core$ mvn clean test</pre>

If you need use pin dialog (default test with 0000) see [OpenSCTestBase](https://github.com/Emergya/opensc-testing/blob/master/opensc-testing-core/src/main/java/org/opensc/testing/OpenSCTestBase.java) and change:
<pre>...
	protected boolean requestPin = false;
...</pre>

If your slot it's diferent than <strong>1</strong> modify [SecurityUtils](https://github.com/Emergya/opensc-testing/blob/master/opensc-testing-core/src/main/java/org/opensc/testing/SecurityUtils.java): 
<pre>...
	/**
	 * SmartCard Reader slot (defaults 1)
	 */
	public static String SLOT = "1"; //TODO parametrize
...</pre>

