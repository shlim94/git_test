/*!
 * @license Open source under BSD 2-clause (http://choosealicense.com/licenses/bsd-2-clause/)
 * Copyright (c) 2015, Curtis Bratton
 * All rights reserved.
 */
function getPaletteValue(pName){
	
	var PALETTE;
		
	switch(pName){
		case "Material" :
			PALETTE = [
				   d3.rgb(29, 178, 245),
			        d3.rgb(245, 86, 74),
			        d3.rgb(151, 201, 92),
			        d3.rgb(255, 199, 32),
			        d3.rgb(235, 53, 115),
			        d3.rgb(166, 61, 184),
			        d3.rgb(79, 228, 255),
			        d3.rgb(255, 136, 124),
			        d3.rgb(126, 176, 67),
			        d3.rgb(230, 174, 7),
			        d3.rgb(255, 103, 165),
			        d3.rgb(216, 111, 234),
			        d3.rgb(0, 128, 195),
			        d3.rgb(195, 36, 24),
			        d3.rgb(101, 151, 42),
			        d3.rgb(205, 149, 0),
			        d3.rgb(185, 3, 65),
			        d3.rgb(116, 11, 134)
				 ];
		 break;
		case "Soft Pastel" :
			PALETTE = [
				d3.rgb(96, 166, 159),
                d3.rgb(120, 182, 217),
                d3.rgb(102, 130, 187),
                d3.rgb(163, 113, 130),
                d3.rgb(238, 186, 105),
                d3.rgb(144, 186, 88),
                d3.rgb(69, 108, 104),
                d3.rgb(117, 101, 164),
                d3.rgb(146, 216, 209),
                d3.rgb(95, 157, 192),
                d3.rgb(152, 180, 237),
                d3.rgb(213, 163, 180),
                d3.rgb(213, 161, 80),
                d3.rgb(119, 161, 63),
                d3.rgb(119, 158, 154),
                d3.rgb(167, 151, 214),
                d3.rgb(46, 116, 109),
                d3.rgb(70, 132, 167),
                d3.rgb(52, 80, 137),
                d3.rgb(113, 63, 80),
                d3.rgb(188, 136, 55),
                d3.rgb(94, 136, 38),
                d3.rgb(94, 133, 129),
                d3.rgb(67, 51, 114)
			];
		break;
	    case "Harmony Light" :
			PALETTE = [
				d3.rgb(252, 182, 94),
                d3.rgb(103, 158, 197),
                d3.rgb(173, 121, 206),
                d3.rgb(122, 189, 92),
                d3.rgb(225, 142, 146),
                d3.rgb(182, 214, 35),
                d3.rgb(183, 171, 234),
                d3.rgb(133, 219, 213),
                d3.rgb(227, 157, 69),
                d3.rgb(153, 208, 247),
                d3.rgb(223, 171, 255),
                d3.rgb(97, 164, 67),
                d3.rgb(200, 117, 121),
                d3.rgb(157, 189, 10),
                d3.rgb(158, 146, 209),
                d3.rgb(108, 194, 188),
                d3.rgb(202, 132, 44),
                d3.rgb(53, 108, 147),
                d3.rgb(123, 71, 156),
                d3.rgb(72, 139, 42),
                d3.rgb(175, 92, 96),
                d3.rgb(132, 164, 0),
                d3.rgb(133, 121, 184),
                d3.rgb(83, 169, 163)
			];
	    break;
	    case "Pastel" :
			PALETTE = [
				d3.rgb(187, 120, 98),
                d3.rgb(112, 179, 161),
                d3.rgb(187, 98, 106),
                d3.rgb(5, 125, 133),
                d3.rgb(171, 57, 75),
                d3.rgb(218, 197, 153),
                d3.rgb(21, 52, 89),
                d3.rgb(177, 210, 198),
                d3.rgb(237, 170, 148),
                d3.rgb(87, 154, 136),
                d3.rgb(237, 148, 156),
                d3.rgb(55, 175, 183),
                d3.rgb(221, 107, 125),
                d3.rgb(193, 172, 128),
                d3.rgb(71, 102, 139),
                d3.rgb(152, 185, 173),
                d3.rgb(137, 70, 48),
                d3.rgb(62, 129, 111),
                d3.rgb(137, 48, 56),
                d3.rgb(30, 150, 158),
                d3.rgb(196, 82, 100),
                d3.rgb(168, 147, 103),
                d3.rgb(46, 77, 114),
                d3.rgb(127, 160, 148)
			];
		break;
	    case "Bright" :
			PALETTE = [
				d3.rgb(112, 201, 47),
                d3.rgb(248, 202, 0),
                d3.rgb(189, 21, 80),
                d3.rgb(233, 127, 2),
                d3.rgb(157, 65, 156),
                d3.rgb(126, 68, 82),
                d3.rgb(154, 181, 126),
                d3.rgb(54, 163, 166),
                d3.rgb(87, 176, 22),
                d3.rgb(223, 177, 0),
                d3.rgb(239, 71, 130),
                d3.rgb(255, 177, 52),
                d3.rgb(207, 115, 206),
                d3.rgb(176, 118, 132),
                d3.rgb(129, 156, 101),
                d3.rgb(104, 213, 216),
                d3.rgb(62, 151, 0),
                d3.rgb(198, 152, 0),
                d3.rgb(214, 46, 105),
                d3.rgb(183, 77, 0),
                d3.rgb(182, 90, 181),
                d3.rgb(151, 93, 107),
                d3.rgb(104, 131, 76),
                d3.rgb(4, 113, 116)
			];
		break;
	    case "Soft" :
			PALETTE = [
				d3.rgb(203, 200, 123),
                d3.rgb(154, 181, 126),
                d3.rgb(229, 82, 83),
                d3.rgb(126, 68, 82),
                d3.rgb(232, 194, 103),
                d3.rgb(86, 80, 119),
                d3.rgb(107, 171, 172),
                d3.rgb(173, 96, 130),
                d3.rgb(178, 175, 98),
                d3.rgb(129, 156, 101),
                d3.rgb(255, 132, 133),
                d3.rgb(176, 118, 132),
                d3.rgb(207, 169, 78),
                d3.rgb(136, 130, 169),
                d3.rgb(82, 146, 147),
                d3.rgb(223, 146, 180),
                d3.rgb(153, 150, 73),
                d3.rgb(104, 131, 76),
                d3.rgb(179, 32, 33),
                d3.rgb(151, 93, 107),
                d3.rgb(182, 144, 53),
                d3.rgb(111, 105, 144),
                d3.rgb(57, 121, 122),
                d3.rgb(123, 46, 80)
			];
		break;
	    case "Ocean" :
			PALETTE = [
				d3.rgb(117, 192, 153),
                d3.rgb(172, 195, 113),
                d3.rgb(55, 138, 138),
                d3.rgb(95, 162, 106),
                d3.rgb(6, 73, 112),
                d3.rgb(56, 197, 210),
                d3.rgb(0, 167, 198),
                d3.rgb(111, 132, 187),
                d3.rgb(92, 167, 128),
                d3.rgb(147, 170, 88),
                d3.rgb(105, 188, 188),
                d3.rgb(145, 212, 156),
                d3.rgb(56, 123, 162),
                d3.rgb(31, 172, 185),
                d3.rgb(50, 217, 248),
                d3.rgb(161, 182, 237),
                d3.rgb(67, 142, 103),
                d3.rgb(122, 145, 63),
                d3.rgb(5, 88, 88),
                d3.rgb(45, 112, 56),
                d3.rgb(31, 95, 137),
                d3.rgb(6, 147, 160),
                d3.rgb(0, 117, 148),
                d3.rgb(61, 82, 137)
			];
		break;
	    case "Office" :
			PALETTE = [
				d3.rgb(95, 139, 149),
                d3.rgb(186, 77, 81),
                d3.rgb(175, 138, 83),
                d3.rgb(149, 95, 113),
                d3.rgb(133, 150, 102),
                d3.rgb(126, 104, 140),
                d3.rgb(145, 189, 199),
                d3.rgb(236, 127, 131),
                d3.rgb(225, 188, 133),
                d3.rgb(199, 145, 163),
                d3.rgb(183, 200, 152),
                d3.rgb(176, 154, 190),
                d3.rgb(45, 89, 99),
                d3.rgb(136, 27, 31),
                d3.rgb(125, 88, 33),
                d3.rgb(99, 45, 63),
                d3.rgb(83, 100, 52),
                d3.rgb(76, 54, 90)
			];
		break;
	    case "Vintage" :
			PALETTE = [
				d3.rgb(222, 164, 132),
                d3.rgb(239, 197, 156),
                d3.rgb(203, 113, 94),
                d3.rgb(235, 150, 146),
                d3.rgb(168, 92, 76),
                d3.rgb(242, 192, 181),
                d3.rgb(201, 99, 116),
                d3.rgb(221, 149, 108),
                d3.rgb(197, 139, 107),
                d3.rgb(214, 172, 131),
                d3.rgb(253, 163, 144),
                d3.rgb(210, 125, 121),
                d3.rgb(218, 142, 126),
                d3.rgb(217, 167, 156),
                d3.rgb(251, 149, 166),
                d3.rgb(196, 124, 83),
                d3.rgb(172, 114, 82),
                d3.rgb(189, 147, 106),
                d3.rgb(153, 63, 44),
                d3.rgb(185, 100, 96),
                d3.rgb(118, 42, 26),
                d3.rgb(192, 142, 131),
                d3.rgb(151, 49, 66),
                d3.rgb(177, 99, 58)
			];
		break;
	    case "Violet" :
	    	PALETTE = [
	    		d3.rgb(209, 161, 209),
                d3.rgb(238, 172, 197),
                d3.rgb(123, 86, 133),
                d3.rgb(126, 124, 173),
                d3.rgb(161, 61, 115),
                d3.rgb(91, 65, 171),
                d3.rgb(226, 135, 226),
                d3.rgb(104, 156, 193),
                d3.rgb(184, 136, 184),
                d3.rgb(213, 147, 172),
                d3.rgb(173, 136, 183),
                d3.rgb(176, 174, 223),
                d3.rgb(211, 111, 165),
                d3.rgb(141, 115, 221),
                d3.rgb(201, 110, 201),
                d3.rgb(154, 206, 243),
                d3.rgb(159, 111, 159),
                d3.rgb(188, 122, 147),
                d3.rgb(148, 111, 158),
                d3.rgb(76, 74, 123),
                d3.rgb(186, 86, 140),
                d3.rgb(116, 90, 196),
                d3.rgb(176, 85, 176),
                d3.rgb(54, 106, 143)
	    	];
		break;
	    case "Carmine" :
			PALETTE = [
				d3.rgb(251, 119, 100),
                d3.rgb(115, 212, 127),
                d3.rgb(254, 216, 94),
                d3.rgb(212, 118, 131),
                d3.rgb(221, 227, 146),
                d3.rgb(117, 122, 178),
                d3.rgb(255, 169, 150),
                d3.rgb(90, 187, 102),
                d3.rgb(229, 191, 69),
                d3.rgb(255, 168, 181),
                d3.rgb(196, 202, 121),
                d3.rgb(167, 172, 228),
                d3.rgb(201, 69, 50),
                d3.rgb(65, 162, 77),
                d3.rgb(204, 166, 44),
                d3.rgb(162, 68, 81),
                d3.rgb(171, 177, 96),
                d3.rgb(67, 72, 128)
			];
		break;
	    case "Dark Moon" :
			PALETTE = [
				d3.rgb(77, 218, 193),
                d3.rgb(244, 201, 154),
                d3.rgb(128, 221, 155),
                d3.rgb(249, 152, 179),
                d3.rgb(74, 170, 160),
                d3.rgb(165, 174, 241),
                d3.rgb(52, 193, 168),
                d3.rgb(219, 176, 129),
                d3.rgb(103, 196, 130),
                d3.rgb(224, 127, 154),
                d3.rgb(124, 220, 210),
                d3.rgb(140, 149, 216),
                d3.rgb(27, 168, 143),
                d3.rgb(194, 151, 104),
                d3.rgb(78, 171, 105),
                d3.rgb(199, 102, 129),
                d3.rgb(24, 120, 110),
                d3.rgb(115, 124, 191)
			];
		break;
	    case "Soft Blue" :
			PALETTE = [
				d3.rgb(122, 184, 235),
                d3.rgb(151, 218, 151),
                d3.rgb(250, 203, 134),
                d3.rgb(231, 134, 131),
                d3.rgb(131, 155, 218),
                d3.rgb(77, 183, 190),
                d3.rgb(97, 159, 210),
                d3.rgb(126, 193, 126),
                d3.rgb(225, 178, 109),
                d3.rgb(206, 109, 106),
                d3.rgb(106, 130, 193),
                d3.rgb(52, 158, 165),
                d3.rgb(72, 134, 185),
                d3.rgb(101, 168, 101),
                d3.rgb(200, 153, 84),
                d3.rgb(181, 84, 81),
                d3.rgb(81, 105, 168),
                d3.rgb(27, 133, 140)
			];
		break;
	    case "Dark Violet" :
			PALETTE = [
				d3.rgb(156, 99, 255),
                d3.rgb(100, 192, 100),
                d3.rgb(238, 173, 81),
                d3.rgb(210, 80, 75),
                d3.rgb(75, 107, 191),
                d3.rgb(45, 167, 176),
                d3.rgb(206, 149, 255),
                d3.rgb(75, 167, 75),
                d3.rgb(213, 148, 56),
                d3.rgb(255, 130, 125),
                d3.rgb(125, 157, 241),
                d3.rgb(95, 217, 226),
                d3.rgb(106, 49, 205),
                d3.rgb(50, 142, 50),
                d3.rgb(188, 123, 31),
                d3.rgb(160, 30, 25),
                d3.rgb(25, 57, 141),
                d3.rgb(0, 117, 126)
			];
		break;
	    case "Green Mist" :
			PALETTE = [
				d3.rgb(60, 186, 178),
                d3.rgb(142, 217, 98),
                d3.rgb(91, 157, 149),
                d3.rgb(239, 204, 124),
                d3.rgb(241, 146, 159),
                d3.rgb(77, 141, 171),
                d3.rgb(110, 236, 228),
                d3.rgb(117, 192, 73),
                d3.rgb(141, 207, 199),
                d3.rgb(214, 179, 99),
                d3.rgb(216, 121, 134),
                d3.rgb(127, 191, 221),
                d3.rgb(10, 136, 128),
                d3.rgb(92, 167, 48),
                d3.rgb(41, 107, 99),
                d3.rgb(189, 154, 74),
                d3.rgb(191, 96, 109),
                d3.rgb(27, 91, 121)
			];
		break;

		default:break;
	}
	
	return PALETTE;
}