/*!
 * @license Open source under BSD 2-clause (http://choosealicense.com/licenses/bsd-2-clause/)
 * Copyright (c) 2015, Curtis Bratton
 * All rights reserved.
 */
function getPivotSample(){
		
	var sales = [ {
	    "id": 10253,
	    "region": "South America",
	    "country": "Brazil",
	    "city": "Rio de Janeiro",
	    "amount": 5260,
	    "date": new Date("2013-01-17")
	}, {
	    "id": 10254,
	    "region": "South America",
	    "country": "Argentina",
	    "city": "Buenos Aires",
	    "amount": 2790,
	    "date": new Date("2013-01-21")
	}, {
	    "id": 10255,
	    "region": "South America",
	    "country": "Paraguay",
	    "city": "Asuncion",
	    "amount": 3140,
	    "date": new Date("2013-01-01")
	}, {
	    "id": 10264,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 2220,
	    "date": new Date("2013-01-15")
	}, {
	    "id": 10278,
	    "region": "South America",
	    "country": "Brazil",
	    "city": "Rio de Janeiro",
	    "amount": 1240,
	    "date": new Date("2013-02-03")
	}, {
	    "id": 10279,
	    "region": "South America",
	    "country": "Argentina",
	    "city": "Buenos Aires",
	    "amount": 315,
	    "date": new Date("2013-02-04")
	}, {
	    "id": 10280,
	    "region": "South America",
	    "country": "Paraguay",
	    "city": "Asuncion",
	    "amount": 2870,
	    "date": new Date("2013-02-18")
	}, {
	    "id": 10288,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Sydney",
	    "amount": 6040,
	    "date": new Date("2013-02-17")
	}, {
	    "id": 10289,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 2205,
	    "date": new Date("2013-02-08")
	},  {
	    "id": 10292,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 2325,
	    "date": new Date("2013-02-15")
	}, {
	    "id": 10293,
	    "region": "South America",
	    "country": "Argentina",
	    "city": "Buenos Aires",
	    "amount": 930,
	    "date": new Date("2013-02-21")
	}, {
	    "id": 10300,
	    "region": "South America",
	    "country": "Brazil",
	    "city": "Rio de Janeiro",
	    "amount": 640,
	    "date": new Date("2013-03-08")
	}, {
	    "id": 10301,
	    "region": "South America",
	    "country": "Argentina",
	    "city": "Buenos Aires",
	    "amount": 735,
	    "date": new Date("2013-03-19")
	}, {
	    "id": 10302,
	    "region": "South America",
	    "country": "Paraguay",
	    "city": "Asuncion",
	    "amount": 2520,
	    "date": new Date("2013-03-20")
	},{
	    "id": 10310,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Sydney",
	    "amount": 5120,
	    "date": new Date("2013-03-08")
	}, {
	    "id": 10311,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 1980,
	    "date": new Date("2013-03-17")
	},  {
	    "id": 10314,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Sydney",
	    "amount": 5460,
	    "date": new Date("2013-03-19")
	},{
	    "id": 10316,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 2610,
	    "date": new Date("2013-03-04")
	},{
	    "id": 10325,
	    "region": "South America",
	    "country": "Brazil",
	    "city": "Rio de Janeiro",
	    "amount": 4420,
	    "date": new Date("2013-04-08")
	}, {
	    "id": 10326,
	    "region": "South America",
	    "country": "Argentina",
	    "city": "Buenos Aires",
	    "amount": 1755,
	    "date": new Date("2013-04-13")
	}, {
	    "id": 10327,
	    "region": "South America",
	    "country": "Paraguay",
	    "city": "Asuncion",
	    "amount": 2580,
	    "date": new Date("2013-04-15")
	},{
	    "id": 10335,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Sydney",
	    "amount": 1940,
	    "date": new Date("2013-04-23")
	}, {
	    "id": 10336,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 1980,
	    "date": new Date("2013-04-21")
	},{
	    "id": 10339,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 3585,
	    "date": new Date("2013-04-01")
	}, {
	    "id": 10341,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 4005,
	    "date": new Date("2013-04-04")
	}, {
	    "id": 10349,
	    "region": "South America",
	    "country": "Brazil",
	    "city": "Rio de Janeiro",
	    "amount": 2260,
	    "date": new Date("2013-05-19")
	}, {
	    "id": 10350,
	    "region": "South America",
	    "country": "Argentina",
	    "city": "Buenos Aires",
	    "amount": 1215,
	    "date": new Date("2013-05-23")
	}, {
	    "id": 10351,
	    "region": "South America",
	    "country": "Paraguay",
	    "city": "Asuncion",
	    "amount": 1210,
	    "date": new Date("2013-05-08")
	}, {
	    "id": 10359,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Sydney",
	    "amount": 3740,
	    "date": new Date("2013-05-24")
	}, {
	    "id": 10360,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 990,
	    "date": new Date("2013-05-02")
	},  {
	    "id": 10368,
	    "region": "South America",
	    "country": "Brazil",
	    "city": "Rio de Janeiro",
	    "amount": 5480,
	    "date": new Date("2013-06-24")
	}, {
	    "id": 10369,
	    "region": "South America",
	    "country": "Argentina",
	    "city": "Buenos Aires",
	    "amount": 2355,
	    "date": new Date("2013-06-10")
	}, {
	    "id": 10370,
	    "region": "South America",
	    "country": "Paraguay",
	    "city": "Asuncion",
	    "amount": 1960,
	    "date": new Date("2013-06-23")
	}, {
	    "id": 10378,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Sydney",
	    "amount": 2100,
	    "date": new Date("2013-06-06")
	}, {
	    "id": 10379,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 3570,
	    "date": new Date("2013-06-10")
	}, {
	    "id": 10383,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Sydney",
	    "amount": 1460,
	    "date": new Date("2013-06-17")
	}, {
	    "id": 10392,
	    "region": "South America",
	    "country": "Brazil",
	    "city": "Rio de Janeiro",
	    "amount": 4500,
	    "date": new Date("2013-07-03")
	}, {
	    "id": 10393,
	    "region": "South America",
	    "country": "Argentina",
	    "city": "Buenos Aires",
	    "amount": 4575,
	    "date": new Date("2013-07-21")
	}, {
	    "id": 10394,
	    "region": "South America",
	    "country": "Paraguay",
	    "city": "Asuncion",
	    "amount": 2310,
	    "date": new Date("2013-07-18")
	}, {
	    "id": 10402,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Sydney",
	    "amount": 4980,
	    "date": new Date("2013-07-19")
	}, {
	    "id": 10403,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 2580,
	    "date": new Date("2013-07-04")
	},  {
	    "id": 10412,
	    "region": "South America",
	    "country": "Brazil",
	    "city": "Rio de Janeiro",
	    "amount": 2300,
	    "date": new Date("2013-08-09")
	}, {
	    "id": 10413,
	    "region": "South America",
	    "country": "Argentina",
	    "city": "Buenos Aires",
	    "amount": 2895,
	    "date": new Date("2013-08-15")
	}, {
	    "id": 10414,
	    "region": "South America",
	    "country": "Paraguay",
	    "city": "Asuncion",
	    "amount": 350,
	    "date": new Date("2013-08-20")
	},{
	    "id": 10422,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Sydney",
	    "amount": 2220,
	    "date": new Date("2013-08-16")
	}, {
	    "id": 10423,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 1575,
	    "date": new Date("2013-08-23")
	},  {
	    "id": 10427,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 4635,
	    "date": new Date("2013-08-04")
	}, {
	    "id": 10429,
	    "region": "South America",
	    "country": "Brazil",
	    "city": "Rio de Janeiro",
	    "amount": 6020,
	    "date": new Date("2013-08-02")
	},  {
	    "id": 10437,
	    "region": "South America",
	    "country": "Brazil",
	    "city": "Rio de Janeiro",
	    "amount": 780,
	    "date": new Date("2013-09-08")
	}, {
	    "id": 10438,
	    "region": "South America",
	    "country": "Argentina",
	    "city": "Buenos Aires",
	    "amount": 2370,
	    "date": new Date("2013-09-19")
	}, {
	    "id": 10439,
	    "region": "South America",
	    "country": "Paraguay",
	    "city": "Asuncion",
	    "amount": 1410,
	    "date": new Date("2013-09-09")
	}, {
	    "id": 10447,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Sydney",
	    "amount": 5080,
	    "date": new Date("2013-09-25")
	}, {
	    "id": 10448,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 1125,
	    "date": new Date("2013-09-13")
	}, {
	    "id": 10457,
	    "region": "South America",
	    "country": "Brazil",
	    "city": "Rio de Janeiro",
	    "amount": 2320,
	    "date": new Date("2013-10-18")
	}, {
	    "id": 10458,
	    "region": "South America",
	    "country": "Argentina",
	    "city": "Buenos Aires",
	    "amount": 4260,
	    "date": new Date("2013-10-24")
	}, {
	    "id": 10459,
	    "region": "South America",
	    "country": "Paraguay",
	    "city": "Asuncion",
	    "amount": 840,
	    "date": new Date("2013-10-18")
	},{
	    "id": 10467,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Sydney",
	    "amount": 4260,
	    "date": new Date("2013-10-01")
	}, {
	    "id": 10468,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 4245,
	    "date": new Date("2013-10-26")
	},{
	    "id": 10477,
	    "region": "South America",
	    "country": "Brazil",
	    "city": "Rio de Janeiro",
	    "amount": 4180,
	    "date": new Date("2013-11-15")
	}, {
	    "id": 10478,
	    "region": "South America",
	    "country": "Argentina",
	    "city": "Buenos Aires",
	    "amount": 3720,
	    "date": new Date("2013-11-25")
	}, {
	    "id": 10479,
	    "region": "South America",
	    "country": "Paraguay",
	    "city": "Asuncion",
	    "amount": 2730,
	    "date": new Date("2013-11-08")
	}, {
	    "id": 10487,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Sydney",
	    "amount": 4960,
	    "date": new Date("2013-11-04")
	}, {
	    "id": 10488,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 2280,
	    "date": new Date("2013-11-13")
	},  {
	    "id": 10497,
	    "region": "South America",
	    "country": "Brazil",
	    "city": "Rio de Janeiro",
	    "amount": 4080,
	    "date": new Date("2013-12-21")
	}, {
	    "id": 10498,
	    "region": "South America",
	    "country": "Argentina",
	    "city": "Buenos Aires",
	    "amount": 4140,
	    "date": new Date("2013-12-22")
	}, {
	    "id": 10499,
	    "region": "South America",
	    "country": "Paraguay",
	    "city": "Asuncion",
	    "amount": 390,
	    "date": new Date("2013-12-04")
	},{
	    "id": 10507,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Sydney",
	    "amount": 4460,
	    "date": new Date("2013-12-12")
	}, {
	    "id": 10508,
	    "region": "Australia",
	    "country": "Australia",
	    "city": "Melbourne",
	    "amount": 3825,
	    "date": new Date("2013-12-13")
	}];
	
	return sales;
}

