for name in any_*
	do
		echo $name
		len=`expr length $name`
		newname=${name:0:${len}-4}
		python getHist.py $newname
	done
git add get*
git commit -m "new histogram"
git push https://github.com/TingshanHuang/AnomalyDetectionWithDNSData.git
