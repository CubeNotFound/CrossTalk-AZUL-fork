





var preload_text = 'שאבא יחזור הביתה...';



var urls = new Array(

	'./imgs/he-il/patience.gif'

);



var preload_urls = new Array(

	'./imgs/spacer.gif',

	'./imgs/doron.gif',

	'./imgs/he-il/board.gif',

	'./imgs/he-il/title.gif',

	'./imgs/gray_right_top.gif',

	'./imgs/gray_right_bottom.gif',

	'./imgs/gray.gif',

	'./imgs/green.gif',

	'./imgs/gray_top.gif',

	'./imgs/gray_bottom.gif',

	'./imgs/green_left_top.gif',

	'./imgs/green_top.gif',

	'./imgs/green_bottom.gif',

	'./imgs/green_left_bottom.gif',

	'./imgs/green_empty_circle.gif',

	'./imgs/gray_empty_circle.gif',

	'./imgs/gray_circle.gif',

	'./imgs/green_circle.gif',

	'./imgs/gray_a1.gif', './imgs/gray_a2.gif', './imgs/gray_a3.gif', './imgs/gray_a4.gif', './imgs/gray_a5.gif', './imgs/gray_a6.gif', './imgs/gray_a7.gif', './imgs/gray_a8.gif',

	'./imgs/gray_b1.gif', './imgs/gray_b2.gif', './imgs/gray_b3.gif', './imgs/gray_b4.gif', './imgs/gray_b5.gif', './imgs/gray_b6.gif', './imgs/gray_b7.gif', './imgs/gray_b8.gif',

	'./imgs/gray_c1.gif', './imgs/gray_c2.gif', './imgs/gray_c3.gif', './imgs/gray_c4.gif', './imgs/gray_c5.gif', './imgs/gray_c6.gif', './imgs/gray_c7.gif', './imgs/gray_c8.gif',

	'./imgs/green_a1.gif', './imgs/green_a2.gif', './imgs/green_a3.gif', './imgs/green_a4.gif', './imgs/green_a5.gif', './imgs/green_a6.gif', './imgs/green_a7.gif', './imgs/green_a8.gif',

	'./imgs/green_b1.gif', './imgs/green_b2.gif', './imgs/green_b3.gif', './imgs/green_b4.gif', './imgs/green_b5.gif', './imgs/green_b6.gif', './imgs/green_b7.gif', './imgs/green_b8.gif',

	'./imgs/green_c1.gif', './imgs/green_c2.gif', './imgs/green_c3.gif', './imgs/green_c4.gif', './imgs/green_c5.gif', './imgs/green_c6.gif', './imgs/green_c7.gif', './imgs/green_c8.gif'

);



var balls = new Array(

	new Array(new Array(0, 0), new Array(0, 0), new Array(0, 0), new Array(0, 0), new Array(0, 0), new Array(0, 0), new Array(0, 0), new Array(0, 0), new Array(0, 0)),

	new Array(new Array(0, 0), new Array(0, 0), new Array(0, 0), new Array(0, 0), new Array(0, 0), new Array(0, 0), new Array(0, 0), new Array(0, 0), new Array(0, 0))

);



var preload_imgs, transition_id, preload_id, preload_per_file;

var preload_done = 0, perload_light_text = 0, transition_stage = 0, preload_last_file = -1;



var user_inviter, user_me, user_him, old_img, alt_board;

var remote_loaded = false, loaded = false, remote_restarted = false, restarted = false, game_restarted = false, in_game = false, my_turn = false, blink_id = false, move = false, free_move = false, closed = false, stuck = false, old_active = false;

var his_name = "", my_name = "", old_turn = "", old_class = "", old_status = "", stats="";

var game_num = 0, my_color = 0, to_delete = 0, game_stage = 0, my_wins = 0, his_wins = 0;

var users = window.external.Users;

var balls_left = new Array(), move_from = new Array(2), forbidden = new Array(new Array(), new Array()), existing = new Array(new Array(), new Array());

var board = new Array(new Array(8), new Array(8), new Array(8)), board_balls = new Array(new Array(8), new Array(8), new Array(8));



function show_all(obj, recurse, ident) {



	ident = ident ? ident : 0;



	ident_text = "";

	for(i = -1; i < Number(ident); i++)

		ident_text += "\t";



	msg = typeof(obj) + " (\n";

	i = 0;

	for(element in obj) {



//		if(element.substr(0, 2) == "on") {



		if(!obj[element].length || !recurse) {

			msg += ident_text + "[" + element + "] => " + obj[element] + "\n";

		} else {

			msg += ident_text + "[" + element + "] => " + show_all(obj[element], true, Number(ident) + 1) + "\n";

		}



//		if(!(++i % 3))

//			msg += "\n";



//		}



	}



	ident_text = "";

	for(i = 0; i < Number(ident); i++)

		ident_text += "\t";



	msg += ident_text + ")";



	if(ident == 0) {

		alert(msg);

	} else {

		return msg;

	}



}



function preload_urls_imgs(urls) {



	imgs = new Array();



	i = -1;

	for(url in urls) {



		i++;

		imgs[i] = new Image();

		imgs[i].src = urls[url];



	}



	return imgs;



}



function preload() {



	preload_urls_imgs(urls);



	html_preload_table.style.display = "block";



	preload_per_file = preload_text.length / preload_urls.length;



	preload_imgs = preload_urls_imgs(preload_urls);



	if(preload_imgs.length) {

		preload_id = setInterval('preload_progress()', 1);

		preload_progress();

	} else {

		html_preload_table.style.display = "none";

		document.body.onload = new Function('html_main_table.style.display = "block"');

	}



}



function preload_progress() {



	if((preload_last_file + 1) == preload_imgs.length) {



		clearInterval(preload_id);

		transition_id = setInterval('transition()', 1);



		html_main_table.style.display = "block";



		return true;



	}



	if(preload_imgs[preload_last_file + 1].complete) {



		preload_last_file++;



		if((preload_last_file + 1) == preload_imgs.length) {



			preload_light_text = preload_text.length;



		} else {



			preload_done += preload_per_file;

			preload_light_text = Math.floor(preload_done);



		}



		code = "<font class=\"pre_text_light\">" + preload_text.substr(0, preload_light_text) + "</font>";

		if(preload_text.length - preload_light_text) code += "<font class=\"pre_text_dark\">" + preload_text.substr(preload_light_text) + "</font>";



		html_preload_text.innerHTML = code;



		percent = Math.round(preload_light_text / preload_text.length * 100);

		

		html_preload_percent.innerHTML = percent;



	}



}



function transition() {



	transition_stage += 100/15;



	if(Math.round(transition_stage) >= 100) {



		html_preload_table.style.bottom = "0px";

		html_preload_table.style.display = "none";

		html_main_table.style.bottom = "0px";



		clearInterval(transition_id);



		initialize();

		

	} else {



		html_preload_table.style.bottom = Math.round(transition_stage) + "%";

		html_main_table.style.bottom = Math.round(transition_stage) + "%";



	}



}



function initialize() {



	loaded = true;



	user_inviter = users.Inviter;

	user_me = users.Me;

	for(i = 0; i < users.Count; i++) {

		user = users.Item(i);

		if(user != user_me)

			user_him = user;

	}



	my_name = (user_me.Name.length > 8) ?

		user_me.Name.substr(0, 8) :

		user_me.Name;

	his_name = (user_him.Name.length > 8) ?

		user_him.Name.substr(0, 8) :

		user_him.Name;



	html_status_text.innerHTML = "ממתין ל-" + his_name + "...";

	if(remote_loaded)

		start_game();



	Channel_OnTypeChanged();



	window.external.Channel.Initialize();



}



function side_circle(show, clr, num) {



	text = show ? "" : "_empty";



	for(img in document.all) {



		if(

			(((clr != 0) && (img.substr(0, 10) == "html_green")) ||

			((clr != 1) && (img.substr(0, 9) == "html_gray"))) &&

			(num ? (img.substr(img.length - 1) == num) : true)

		)

			document.all[img].src = "./imgs/" + img.substr(5, img.length - 6) + text + "_circle.gif";



	}



}



function end_game(winner) {



	in_game = false;



	if(blink_id) {

		clearInterval(blink_id);

		blink_id = false;

	}



	un_asign();



	if(closed) 

		return true;



	if(winner == user_me) {



		my_wins++;



		if(stuck) {

			stuck = false;

			show_status("" + his_name + " תקוע ואינו יכול לזוז ולכן אתה ניצחת! <a href='#' class='active_status' onclick='restart();'>התחל משחק חדש</a>", false);

		} else {

			show_status("המשחק תם " + my_name + " - ניצחת! <a href='#' class='active_status' onclick='restart();'>התחל משחק חדש</a>", false);

		}



		html_status_text.className = "active_status";



	} else if(winner == user_him) {



		his_wins++;



		if(stuck) {

			stuck = false;

			show_status("" + my_name + ", אתה תקוע ואינך יכול לזוז ולכן הפסדת :( <a href='#' class='active_status' onclick='restart();'>התחל משחק חדש</a>", false);

		} else {

			show_status("המשחק תם " + my_name + " - הפסדת :( <a href='#' class='active_status' onclick='restart();'>התחל משחק חדש</a>", false);

		}



		html_status_text.className = "active_status";



	} else {



		show_status("המשחק הותחל מחדש", false);

		html_status_text.className = "active_status";

		game_restarted = true;

		game_num--;



	}



}



function start_game() {



	in_game = true;



	side_circle(true, -1);

	balls_left[0] = 9;

	balls_left[1] = 9;



	forbidden = new Array(new Array(), new Array());

	existing = new Array(new Array(), new Array());



	my_color = opp(my_turn = ((user_inviter == user_me) && !(game_num % 2)) || ((user_inviter != user_me) && (game_num % 2)));



	game_num++;



	game_stage = 0;



	clear_board();



	for(i = 0; i < board.length; i++)

		for(j = 0; j < board[i].length; j++)

			board[i][j] = -1;



	for(i = 0; i < balls.length; i++)

		for(j = 0; j < balls[i].length; j++)

			balls[i][j] = new Array(-1, j);



	move_from = new Array(-1, -1);

	move = false;

	free_move = false;



	make_turn();



}



function get_board(raw) {



	arr = letter_to_num(raw.substr(5));

	row = arr[0];

	num = arr[1];



	return board[row][num];



}



function del_board(row, num) {



	num = Number(num);

	row = Number(row);



	board[row][num] = -1;



	text = num_to_letter(row, num);



	document.all["html_" + text].src = "./imgs/spacer.gif";



}



function put_board(row, num, clr) {



	num = Number(num);

	row = Number(row);



	board[row][num] = Number(clr);



	clr = clr ? "green" : "gray";



	text = num_to_letter(row, num);



	document.all["html_" + text].src = "./imgs/" + clr + "_" + text + ".gif";

	document.all["html_" + text].style.visibility = "visible";



}



function get_rows() {



	i = -1;

	rows = new Array();



	for(j = 0; j < 3; j++) {

		for(k = 0; k < 7; k += 2) {

			rows[++i] = new Array(

				new Array(j, k),

				new Array(j, k + 1),

				new Array(j, (k != 6) ? (k + 2) : 0)

			);

		}

	}



	for(j = 1; j < 8; j += 2) {

		rows[++i] = new Array(

			new Array(0, j),

			new Array(1, j),

			new Array(2, j)

		);

	}



	return rows;



}



function num_to_letter(row, num) {



	switch(Number(row)) {

		case 0:

			row = "a";

			break;

		case 1:

			row = "b";

			break;

		case 2:

			row = "c";

			break;

	}



	num = Number(num) + 1;



	return row + num;



}



function letter_to_num(raw) {



	switch(raw.substr(0, 1)) {

		case "a":

			row = 0;

			break;

		case "b":

			row = 1;

			break;

		case "c":

			row = 2;

			break;

	}



	num = Number(raw.substr(1)) - 1;



	return new Array(row, num);



}



function old_row() {



	for(i in existing[0]) {

		if(!(

			(board[existing[0][i][0][0]][existing[0][i][0][1]] == my_color) &&

			(board[existing[0][i][1][0]][existing[0][i][1][1]] == my_color) &&

			(board[existing[0][i][2][0]][existing[0][i][2][1]] == my_color)

		)) {

			delete existing[0][i];

		}

	}



	for(i in existing[1]) {

		if(!(

			(board[existing[1][i][0][0]][existing[1][i][0][1]] == opp(my_color)) &&

			(board[existing[1][i][1][0]][existing[1][i][1][1]] == opp(my_color)) &&

			(board[existing[1][i][2][0]][existing[1][i][2][1]] == opp(my_color))

		)) {

			delete existing[1][i];

		}

	}



}



function new_row(clr, row, num) {



	new_rows = 0;

	rows = get_rows();



	for(i in rows) {



		if(

			((rows[i][0][0] == row) && (rows[i][0][1] == num)) ||

			((rows[i][1][0] == row) && (rows[i][1][1] == num)) ||

			((rows[i][2][0] == row) && (rows[i][2][1] == num))

		) {



			if(

				(board[rows[i][0][0]][rows[i][0][1]] == clr) &&

				(board[rows[i][1][0]][rows[i][1][1]] == clr) &&

				(board[rows[i][2][0]][rows[i][2][1]] == clr)

			) {



				old = false;



				for(j in existing[Number(clr != my_color)])

					if(

						((rows[i][0][0] == existing[Number(clr != my_color)][j][0][0]) && (rows[i][0][1] == existing[Number(clr != my_color)][j][0][1])) &&

						((rows[i][1][0] == existing[Number(clr != my_color)][j][1][0]) && (rows[i][1][1] == existing[Number(clr != my_color)][j][1][1])) &&

						((rows[i][2][0] == existing[Number(clr != my_color)][j][2][0]) && (rows[i][2][1] == existing[Number(clr != my_color)][j][2][1]))

					)

						old = true;



				if(!old) {



					if(typeof(forbidden[Number(clr != my_color)]) != "object")

						forbidden[Number(clr != my_color)] = new Array();



					forbid = false;



					for(j in forbidden[Number(clr != my_color)])

						if(

							((rows[i][0][0] == forbidden[Number(clr != my_color)][j][1][0]) && (rows[i][0][1] == forbidden[Number(clr != my_color)][j][1][1])) &&

							((rows[i][1][0] == forbidden[Number(clr != my_color)][j][2][0]) && (rows[i][1][1] == forbidden[Number(clr != my_color)][j][2][1])) &&

							((rows[i][2][0] == forbidden[Number(clr != my_color)][j][3][0]) && (rows[i][2][1] == forbidden[Number(clr != my_color)][j][3][1]))

						)

							forbid = true;



					if(!forbid) {



						forbidden[Number(clr != my_color)].push(new Array(

							0,

							new Array(rows[i][0][0], rows[i][0][1]),

							new Array(rows[i][1][0], rows[i][1][1]),

							new Array(rows[i][2][0], rows[i][2][1])

						));



						if(typeof(existing[Number(clr != my_color)]) != "object")

							existing[Number(clr != my_color)] = new Array();



						existing[Number(clr != my_color)].push(new Array(

							new Array(rows[i][0][0], rows[i][0][1]),

							new Array(rows[i][1][0], rows[i][1][1]),

							new Array(rows[i][2][0], rows[i][2][1])

						));



						new_rows++;



					}



				}



			}



		}



	}



	return (new_rows > 0) ? 1 : 0;



}



function num_balls(user) {



	num = 0;



	for(i in balls[user])

		if(balls[user][i][1] != -1)

			num++;



	return num;



}



function send(data) {



	if(!closed) {



		if(!remote_loaded) {

			initialize();

		} else {

			window.external.Channel.SendData(data);

		}



	}



}



function do_delete(row, num) {



	del_board(row, num);



	arr = search_ball(row, num);

	balls[arr[0]][arr[1]] = new Array(-1, -1);



	old_row();



	to_delete--;



	if(my_turn) {

		send("del_" + row + "_" + num);

	} else {

		if(num_balls(0) == 3)

			free_move = true;

	}



	if(num_balls(0) == 2) {

		end_game(user_him);

	} else if(num_balls(1) == 2) {

		end_game(user_me);

	} else {



		if(!to_delete) {

			my_turn = !my_turn;

			make_turn();

		}



	}



}



function has_near(letter) {



	var img, arr;



	arr = letter_to_num(letter);



	for(img in document.all) {



		if(

			(img.length == 7) && (img.substr(0, 5) == "html_") &&

			(img.substr(5, 1) >= "a") && (img.substr(5, 1) <= "c") &&

			(img.substr(6, 1) >= "1") && (img.substr(6, 1) <= "8")

		) {

			if((get_board(img) == -1) && near(arr[0], arr[1], img.substr(5)))

				return true;

		}



	}



	return false;



}



function near(row, num, letter) {



	arr = letter_to_num(letter);



	if(arr[0] == row) {



		if(num == 0) {

			if((arr[1] == 7) || (arr[1] == 1))

				return true;

		} else if(num == 7) {

			if((arr[1] == 0) || (arr[1] == 6))

				return true;

		} else {

			if(Math.abs(arr[1] - num) == 1)

				return true;

		}



	} else if((arr[1] == num) && ((num % 2) == 1) && (Math.abs(arr[0] - row) == 1)) {



		return true;



	}



	return false;



}



function get_asign() {



	asign = new Array();



	for(img in document.all) {



		if(

			(img.length == 7) && (img.substr(0, 5) == "html_") &&

			(img.substr(5, 1) >= "a") && (img.substr(5, 1) <= "c") &&

			(img.substr(6, 1) >= "1") && (img.substr(6, 1) <= "8")

		) {

			asign[img] = new Array();



			asign[img][0] = document.all[img].style.cursor;

			asign[img][1] = document.all[img].onclick;

		}



	}



	return asign;



}



function set_asign(asign) {



	for(img in document.all) {



		if(

			(img.length == 7) && (img.substr(0, 5) == "html_") &&

			(img.substr(5, 1) >= "a") && (img.substr(5, 1) <= "c") &&

			(img.substr(6, 1) >= "1") && (img.substr(6, 1) <= "8")

		) {

			document.all[img].style.cursor = asign[img][0];

			document.all[img].onclick = asign[img][1];

		}



	}



}



function un_asign() {



	for(img in document.all) {



		if(

			(img.length == 7) && (img.substr(0, 5) == "html_") &&

			(img.substr(5, 1) >= "a") && (img.substr(5, 1) <= "c") &&

			(img.substr(6, 1) >= "1") && (img.substr(6, 1) <= "8")

		) {

			document.all[img].style.cursor = "auto";

			document.all[img].onclick = "";

		}



	}



}



function make_turn_row(row, num) {



	if(!(to_delete = new_row(my_color, row, num))) {



		return false;



	} else {



		show_turn(user_me);

		show_status("בחר חייל של יריבך להסרה", true);



		allowed_1 = new Array();



		for(img in document.all) {



			if(

				(img.length == 7) && (img.substr(0, 5) == "html_") &&

				(img.substr(5, 1) >= "a") && (img.substr(5, 1) <= "c") &&

				(img.substr(6, 1) >= "1") && (img.substr(6, 1) <= "8") &&

				(get_board(img) == opp(my_color))

			) {

				arr = letter_to_num(img.substr(5));

				allowed_1[allowed_1.length] = new Array(arr[0], arr[1]);

			}



		}



		allowed_2 = new Array();

		allowed_2 = allowed_1.concat();

		len = allowed_2.length;



		for(i in existing[1]) {

			for(j in allowed_2) {

				if(

					((allowed_2[j][0] == existing[1][i][0][0]) && (allowed_2[j][1] == existing[1][i][0][1])) ||

					((allowed_2[j][0] == existing[1][i][1][0]) && (allowed_2[j][1] == existing[1][i][1][1])) ||

					((allowed_2[j][0] == existing[1][i][2][0]) && (allowed_2[j][1] == existing[1][i][2][1]))

				) {

					delete allowed_2[j];

					len--;

				}

			}

		}



		allowed = len ? 

			allowed_2 :

			allowed_1;



		un_asign();



		for(i in allowed) {



			img = "html_" + num_to_letter(allowed[i][0], allowed[i][1]);



			document.all[img].style.cursor = "pointer";

			document.all[img].onclick = new Function("do_delete(" + allowed[i][0] + ", " + allowed[i][1] + ")");



		}



	}



	return true;



}



function do_click(row, num) {



	switch(game_stage) {



		case 0:



			send("put_" + row + "_" + num);

			put_board(row, num, my_color);



			clearInterval(blink_id); blink_id = false;

			side_circle(false, my_color, 10 - balls_left[0]);

			balls_left[0]--;



			if(balls_left[0] == 0)

				game_stage++;



			balls[0][8 - balls_left[0]] = new Array(row, num);



			if(!make_turn_row(row, num)) {

				my_turn = false;

				make_turn();

			}



			break;



		case 1:



			if(!move) {



				show_turn(user_me);

				show_status("בחר מטרה או חייל אחר", true);



				if(move_from[0] != -1) {

					clearInterval(blink_id); blink_id = false;

					document.all["html_" + num_to_letter(move_from[0], move_from[1])].src = old_img;

				}



				blink_board(row, num);



				move_from = new Array(row, num);



				un_asign();



				for(img in document.all) {



					if(

						(img.length == 7) && (img.substr(0, 5) == "html_") &&

						(img.substr(5, 1) >= "a") && (img.substr(5, 1) <= "c") &&

						(img.substr(6, 1) >= "1") && (img.substr(6, 1) <= "8") &&

						(((get_board(img) == my_color) && (free_move || has_near(img.substr(5)))) || ((get_board(img) == -1) && (free_move || near(row, num, img.substr(5)))))

					) {

						arr = letter_to_num(img.substr(5));



						document.all[img].style.cursor = "pointer";

						if(get_board(img) == my_color) {

							document.all[img].onclick = new Function("do_click(" + arr[0] + ", " + arr[1] + ")");

						} else {

							document.all[img].onclick = new Function("move = true; do_click(" + arr[0] + ", " + arr[1] + ")");

						}

					}



				}



			} else {



				send("move_" + move_from[0] + "_"  + move_from[1] + "_" + row + "_" + num);



				clearInterval(blink_id); blink_id = false;



				del_board(move_from[0], move_from[1]);



				put_board(row, num, my_color);



				arr = search_ball(move_from[0], move_from[1]);

				balls[arr[0]][arr[1]] = new Array(row, num);



				move = false;



				move_from = new Array(-1, -1);



				old_row();



				if(!make_turn_row(row, num)) {

					my_turn = false;

					make_turn();

				}



			}



			break;



	}



}



function restart() {



	if(closed)

		return true;



	send("restart");



	if(remote_restarted) {



		remote_restarted = false;

		restarted = false;



		if(in_game)

			end_game();

		start_game();



		return true;



	}



	if(in_game) {



		restarted = true;



		old_turn = html_status_text.innerHTML;

		old_class = html_status_text.className;

		html_status_text.innerHTML = "ממתין לאישורו של " + his_name + "...";

		html_status_text.className = "active_status";



		if(my_turn) {

			alt_board = get_asign();

			un_asign();

		}



	} else {



		restarted = true;

		html_status_text.innerHTML = "ממתין ל-" + his_name + "...";



	}



}



function restart_no() {



	send("no_restart");



	html_status_text.innerHTML = old_turn;

	html_status_text.className = old_class;



	if(my_turn)

		set_asign(alt_board);



}



function restart_yes() {



	send("restart");



	remote_restarted = false;

	restarted = false;



	end_game();

	start_game();



}



function Channel_OnDataError() {



	closed = true;



	show_status("תקלה בתקשורת. המשחק הסתיים...", false);

	html_status_text.className = "active_status";



	end_game();



}



function Channel_OnRemoteAppClosed() {



	closed = true;



	show_status("" + his_name + " סגר את המשחק. לא תוכל לשחק לבדך...", false);

	html_status_text.className = "active_status";



	end_game();



}



function show_stats() {



	stats = "מס' משחקים: " + ((game_num > 0) ? (game_num - 1) : 0) + " | ניצחונות שלך: " + my_wins + " | ניצחונות של " + his_name + ": " + his_wins + "";



	old_status = html_status_text.innerHTML;

	old_active = (html_status_text.className == "active_status") ? true : false;



	show_status(stats);

	html_status_text.className = "stats_status";





}



function hide_stats() {



	if(old_status != "") {



		if(html_status_text.innerHTML == stats) {



			show_status(old_status, false);

			html_status_text.className = old_active ? "active_status" : "status";



		}



		old_status = "";

		old_active = false;



	}



}



function show_rules() {



	



}



function Channel_OnDataReceived() {



	data = window.external.Channel.Data;



	if(data == "no_restart") {



		show_status("<font class=\"active_status\">" + his_name + " מסרב להתחיל מחדש את המשחק</font><br />", false);

		html_status_text.innerHTML += old_turn;

		html_status_text.className = old_class;



		if(my_turn)

			set_asign(alt_board);



	} else if(data == "restart") {



		if(in_game) {



			if(restarted) {



				remote_restarted = false;

				restarted = false;



				end_game();

				start_game();



			} else {



				remote_restarted = true;



				old_turn = html_status_text.innerHTML;

				old_class = html_status_text.className;

				show_status("" + his_name + " מעוניין להתחיל מחדש את המשחק, אתה מסכים? <a href='#' class='active_status' onclick='restart_yes();'>כן</a> <a href='#' class='active_status' onclick='restart_no();'>לא</a>", false);

				html_status_text.className = "active_status";



				if(my_turn) {

					alt_board = get_asign();

					un_asign();

				}



			}



		} else {



			remote_restarted = true;

			show_status("" + his_name + " מעוניין בעוד משחק וממתין לך... <a href='#' class='active_status' onclick='restart();'>התחל משחק חדש</a>", false);

			html_status_text.className = "active_status";



			if(restarted) {



				remote_restarted = false;

				restarted = false;



				start_game();



			}



		}



	} else {



		if(!loaded) {



			initalize();

			return true;



		}



		if(data == "stuck") {



			stuck = true;

			end_game(user_me);



		} else if(data.substr(0, 4) == "put_") {



			row = data.substr(4, 1);

			num = data.substr(6, 1);



			put_board(row, num, opp(my_color));



			side_circle(false, opp(my_color), 10 - balls_left[1]);

			balls_left[1]--;



			balls[1][8 - balls_left[1]] = new Array(Number(row), Number(num));



			if(!(to_delete = new_row(opp(my_color), row, num))) {



				my_turn = true;

				make_turn();



			}



		} else if(data.substr(0, 4) == "del_") {



			row = data.substr(4, 1);

			num = data.substr(6, 1);



			do_delete(row, num);



		} else if(data.substr(0, 5) == "move_") {



			row1 = data.substr(5, 1);

			num1 = data.substr(7, 1);

		

			del_board(row1, num1);



			row2 = data.substr(9, 1);

			num2 = data.substr(11, 1);

		

			put_board(row2, num2, opp(my_color));



			arr = search_ball(row1, num1);

			balls[arr[0]][arr[1]] = new Array(row2, num2);



			old_row();



			if(!(to_delete = new_row(opp(my_color), row2, num2))) {



				my_turn = true;

				make_turn();



			}



		}



	}



}



function opp(clr) {



	return (!clr ? 1 : 0);



}



function search_ball(row, num) {



	for(i = 0; i < balls.length; i++)

		for(j = 0; j < balls[i].length; j++)

			if((balls[i][j][0] == row) && (balls[i][j][1] == num))

				return new Array(i, j);



}



function make_turn() {



	show_turn(my_turn ? user_me : user_him);



	if(my_turn) {



		for(i in forbidden[0]) {

			forbidden[0][i][0]++;

			if(forbidden[0][i][0] == 3)

				delete forbidden[0][i];

		}



		switch(game_stage) {



			case 0:



				show_status("מקם חייל", true);



				un_asign();



				for(img in document.all) {



					if(

						(img.length == 7) && (img.substr(0, 5) == "html_") &&

						(img.substr(5, 1) >= "a") && (img.substr(5, 1) <= "c") &&

						(img.substr(6, 1) >= "1") && (img.substr(6, 1) <= "8") &&

						(get_board(img) == -1)

					) {

						arr = letter_to_num(img.substr(5));



						document.all[img].style.cursor = "pointer";

						document.all[img].onclick = new Function("do_click(" + arr[0] + ", " + arr[1] + ")");

					}



				}



				blink_side(my_color, 10 - balls_left[0]);



				break;



			case 1:



				show_status("בחר חייל להזזה", true);



				un_asign();



				stuck = true;



				for(img in document.all) {





					if(

						(img.length == 7) && (img.substr(0, 5) == "html_") &&

						(img.substr(5, 1) >= "a") && (img.substr(5, 1) <= "c") &&

						(img.substr(6, 1) >= "1") && (img.substr(6, 1) <= "8") &&

						(get_board(img) == my_color) && (free_move || has_near(img.substr(5)))

					) {



						stuck = false;



						arr = letter_to_num(img.substr(5));



						document.all[img].style.cursor = "pointer";

						document.all[img].onclick = new Function("do_click(" + arr[0] + ", " + arr[1] + ")");



					}



				}



				if(stuck == true) {

					send("stuck");

					end_game(user_him);

				}



				break;



		}



	} else {



		for(i in forbidden[1]) {

			forbidden[1][i][0]++;

			if(forbidden[1][i][0] == 3)

				delete forbidden[1][i];

		}



		un_asign();



	}



}



function blink_side(clr, num) {



	if(!blink_id)

		blink_id = setInterval('blink_side(' + clr + ', ' + num + ')', 300);



	clr = clr ? "green" : "gray";



	img = document.all["html_" + clr + num];



	img.src = (img.src.substr(img.src.length - 16) == "empty_circle.gif") ?

		"./imgs/" + clr + "_circle.gif" :

		"./imgs/" + clr + "_empty_circle.gif";



}



function blink_board(row, num) {



	letter = num_to_letter(row, num);



	img = document.all["html_" + letter];



	if(!blink_id) {

		blink_id = setInterval('blink_board(' + row + ', ' + num + ')', 300);

		old_img = img.src;

	}



	img.src = (img.src == old_img) ?

		"./imgs/spacer.gif" :

		old_img;



}



function show_turn(user) {



	if(game_restarted == true) {

		game_restarted = false;

		text = "<font class=\"active_status\">" + html_status_text.innerHTML + "</font><br />";

	} else {

		text = "";

	}



	text += (user == user_me) ?

		("תורך " + my_name + "") :

		("תור " + his_name + "...");



	html_status_text.innerHTML = text;



	html_status_text.className = (user == user_me) ?

		"active_status" :

		"status";



}



function show_status(text, keep) {



	html_status_text.innerHTML = (keep == true) ?

		html_status_text.innerHTML + ", " + text :

		text;



}



function Channel_OnTypeChanged() {



	switch(window.external.Channel.Type) {

		case 0:

			text = "חיבור ישיר";

			break;

		case 1:

			text = "חיבור עקיף";

			break;

		case 2:

			text = "לא מחובר";

			Channel_OnDataError();

			break;

	}



	html_connection_text.innerHTML = text;



}



function Channel_OnRemoteAppLoaded() {



	remote_loaded = true;



//	if(in_game) {

//		initialize();

//		return true;

//	}



	if(loaded) {

		start_game();

	} else {

		initialize();

	}



}



function clear_board() {



	for(img in document.all) {



		if(

			(img.length == 7) && (img.substr(0, 5) == "html_") &&

			(img.substr(5, 1) >= "a") && (img.substr(5, 1) <= "c") &&

			(img.substr(6, 1) >= "1") && (img.substr(6, 1) <= "8")

		) {

			document.all[img].src = "./imgs/spacer.gif";

		}



	}



}