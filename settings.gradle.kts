// Names the built jar, the manifest's Implementation-Title, and the extensionName the integration
// harness matches against. Those must agree — burp.Extension compares the manifest title to the
// -Dburptesting.extension property to decide whether to install the testing tab — so they all come
// from here rather than being set in three places.
rootProject.name = "HTTP3-Adapter"