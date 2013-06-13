GermDB
=========

GermDB originated as a fork of [VxCage] (https://github.com/cuckoobox/vxcage). It is a framework for the creation of a malware repository for research and testing purposes based on the Django web framework. Pieces of the original VxCage code were migrated to run within Django 1.5 and extended.

Currently GermDB is comprised of a single Django application called the Collector which is the interface for adding, searching and retrieveing malware from the respository. Additional applications with be added over time to include functionality for reviewing details of the malware such static analysis, dynamic analysis, etc.

Some improvements to VxCage include:

* Ability to add an originating URL when adding malware to the repository

Dependencies
------------
* [Django] (http://www.djangoproject.com/) version 1.5

License
-------
Released under GPL version 3. See the LICENSE file for full details.

Known bugs
----------

All known bugs will be listed at the [Github issues] (https://github.com/mikedgibson/germdb/issues) page.

How you can help
----------------

Please open issues on [Github] (https://github.com/mikedgibson/germdb/) on topics such as:

* Bug reports, preferably with error logs
* Suggestions for additional modules to analyze the collected malware
* Details on how you use it and suggestions for improvement

Contact details

[Twitter](https://twitter.com/mdgsecurity) - @mdgsecurity
[email](mailto:mike@mdgsecurity.com) - mike@mdgsecurity.com
