using System;
using System.IO;
using System.Text;

namespace Examples
{
	public static class Support
	{
		public static void TestData(string filename)
		{
			if (!File.Exists(filename))
			{
				StringBuilder sb = new StringBuilder ();

				sb.Append("Lorem ipsum dolor sit amet, duo cu nobis epicurei hendrerit, mei agam elit an. Ea facer urbanitas his, voluptua luptatum corrumpit ea vis. An illum persecuti eos. Qui soluta vivendo et, quo meis vocent ex. Et vim vocent dissentiunt.\r\n");
				sb.Append("Alia partem nam cu, at sed etiam ceteros sententiae, placerat perpetua scribentur ex per. Antiopam postulant assueverit ex eum, eu vim aeterno offendit molestiae, pri iisque pertinacia at. In vide platonem his, lucilius eleifend ad his. Duo ullum placerat ad, duo et civibus luptatum. Urbanitas reformidans at per, an solum civibus inciderint sed. Pro debet zril omnesque no, nisl adhuc summo sed ad.\r\n");
				sb.Append("Sit paulo semper et, ad qui labore senserit definiebas, vidisse adipisci ad mei. Affert vivendo minimum vis eu. Per et aeque equidem, cu wisi incorrupte concludaturque quo. Ius ad stet reformidans.\r\n");
				sb.Append("Mei at delenit efficiantur, ei dolorum vocibus facilisi mea, per ad erant quaeque copiosae. Mel in liber interpretaris, ex sed elit suscipiantur. Ad nisl animal aliquid eum. Integre senserit reformidans qui et, labores epicuri constituam at nam. Euismod consetetur id eam, doctus constituam his et, elit legere eu sed.\r\n");
				sb.Append("In pro eirmod tibique indoctum, ex mel quaestio similique. Duo ad magna ancillae expetendis. Eos ut purto eirmod voluptua. At doming sententiae vis. Nibh percipit vel et, ne duo duis labitur aliquid.\r\n");
				sb.Append("Adhuc zril pri ne, verear ullamcorper ut vim. Et tollit facilis quaestio mea, aeque probatus an vis, ex sed choro antiopam. Quis simul evertitur quo ad, an quo primis melius. Nisl tale mei id, ne wisi dissentiet voluptatibus mel, usu offendit indoctum ei. Est at nobis insolens posidonium.\r\n");
				sb.Append("Et mel adhuc erroribus. Eos impetus urbanitas repudiandae ut, ne mea illum tollit pertinax, lorem quando at sit. Ex est option denique fabellas, habeo dolorum recteque id eam. Nam quodsi menandri et, te sit tamquam eruditi ornatus.\r\n");
				sb.Append("Quo eius nihil electram ea, sea tota ipsum postulant id. Diam impedit veritus in pro, sea persius detracto conceptam ne, mei id enim solum dicit. Agam fugit epicurei at mea, eu eos decore aliquid. Homero essent timeam ex has, ius et quod quaeque. Ad vocent tamquam euripidis has, qui everti deleniti ad, stet modus detraxit ut sea.\r\n");
				sb.Append("Novum melius mentitum sea ei, mea no affert deserunt urbanitas, vim tation ridens vocent at. Ad fugit propriae epicurei qui. Mea te reque porro. Per in delectus oporteat postulant.\r\n");
				sb.Append("Sanctus intellegam pri in, per dicta maluisset ad. At eos aliquid accumsan, modus nulla tritani pro et. No duo partem sanctus accommodare, id his putent voluptua rationibus. Usu aliquid expetenda adolescens te. Quo sint dicat constituam et. Nec legendos sententiae ei, regione delectus sed at, sit homero appetere adversarium eu.\r\n");
				sb.Append("Altera dolorum urbanitas nam ne, noluisse postulant mei et. Cibo dicam elaboraret vis te, cu vix hinc perfecto moderatius. Novum euismod sapientem at qui, molestie quaestio ex eam. Atqui possit vis no, sit ex inermis abhorreant. Maiorum vivendum te sed, enim nemore signiferumque mei ex, no postea diceret moderatius cum. Sed alia lorem scaevola ne, iuvaret accusamus consulatu nam id.\r\n");
				sb.Append("Mel at veri errem sensibus, aliquid lucilius assueverit vim at. Mollis adversarium ei sed, eum an epicuri scaevola scripserit, paulo quodsi qui ad. At sit natum iriure singulis, pro quis verterem quaestio te. Commodo propriae definiebas cu nec. Vel at primis quodsi, per veniam bonorum scaevola ne.\r\n");
				sb.Append("Te tibique scriptorem accommodare usu. Ad possim quaerendum mel. Id quidam explicari necessitatibus nam. Ex vide dolor omittam duo, quo vocent diceret verterem no. Usu diam copiosae oportere ea, in noluisse persecuti eos.\r\n");
				sb.Append("Ut mei partem signiferumque, in sed euripidis reprehendunt, ex eum consetetur adipiscing. Mei at mollis virtute, ex mea saepe facilisis. Ferri inciderint eloquentiam vis te, eam congue maluisset no, nostro forensibus maiestatis cu mel. Ut quo tation platonem volutpat. Ei sed purto dolorum legendos, ea unum decore per.\r\n");
				sb.Append("Eu eam erant deleniti, te qui quod nominati. Mel rebum homero ut, enim appareat nominati usu ex. Inani nulla percipitur est an. Eam at tempor pericula scriptorem. Ut vis vide latine.\r\n");
				sb.Append("Ei eam congue exerci accommodare, facilisi consequuntur vix no. Ea solet graece pertinax vel, liber accommodare id pri, ex nostro perpetua laboramus vel. In brute sadipscing cum. Vel ei tale feugiat invenire. Ex est audire conclusionemque.\r\n");
				sb.Append("Et maiorum efficiantur per. Has id maluisset patrioque omittantur, eu quem tollit assueverit vel. Eu nec utamur conceptam, has maiorum appetere instructior ad. Quo eu nisl noster copiosae.\r\n");
				sb.Append("Scripta pertinax honestatis ne eum. Usu at erat everti phaedrum, at vis modo aperiri. Cetero vivendo quaerendum eam ad. Dico aliquando eu cum, putant inciderint vix eu.\r\n");
				sb.Append("At vis lorem conceptam, ad pri vero dicat elaboraret, ad nobis imperdiet constituto duo. Bonorum tacimates et duo, mazim causae propriae sea ne. Mucius tibique argumentum mea eu. Eu usu detracto ocurreret. Id tation libris philosophia pri, vix id corpora democritum.\r\n");
				sb.Append("Nam labores dignissim ut. An pro noluisse erroribus efficiendi, an has nisl malis philosophia. Autem electram democritum ad usu, per paulo propriae ea. Veri utamur in eos, summo debet decore ne \r\n");

				File.WriteAllText(filename, sb.ToString ());
			}
		}
	}
}

