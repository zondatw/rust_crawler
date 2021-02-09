use std::error::Error;
use reqwest;
use reqwest::StatusCode;
use select::document::Document;
use select::predicate::{And, Name, Attr, Class, Predicate};
use url::Url;
use std::collections::HashMap;
use chrono::{Date, NaiveDate, Local, Duration, TimeZone};


fn get_last_page_num(document: &Document) -> i32 {
    document.find(And(Name("span"), Class("last-page")))
        .map(|node| node.text())
        .collect::<String>()
        .trim().parse::<i32>().expect("Get last page number error")
}

fn get_vul_info(vul_report_url: &str) -> HashMap<String, String> {
    let report_body = reqwest::blocking::get(vul_report_url)
        .expect("Report not found")
        .text()
        .expect("Get report body error");

    let mut vul_info = HashMap::new();
    vul_info.insert(String::from("title"), String::from(""));
    vul_info.insert(String::from("last_update"), String::from(""));
    vul_info.insert(String::from("status"), String::from(""));
    vul_info.insert(String::from("risk"), String::from(""));
    vul_info.insert(String::from("type"), String::from(""));
    let report_document = Document::from(report_body.as_str());
    vul_info.insert(
        String::from("title"),
        report_document.find(And(Name("li"), Class("title")).descendant(And(Name("span"), Class("value"))))
            .map(|node| node.text())
            .collect::<String>()
            .trim()
            .to_string()
    );
    vul_info.insert(
        String::from("last_update"),
        report_document.find(And(Name("div"), Class("status-descr")))
            .map(|node| node.text())
            .collect::<String>()
            .split(" : ")
            .collect::<Vec<&str>>()[1]
            .to_string()
    );
    vul_info.insert(
        String::from("status"),
        report_document.find(And(Name("div"), Class("status-label")))
            .map(|node| node.text())
            .collect::<String>()
    );

    for li_node in report_document.find(And(Name("div"), Class("info")).descendant(Name("li"))) {
        let li_text = li_node.text();
        if li_text.starts_with("風險") {
            vul_info.insert(
                String::from("risk"),
                li_text.to_string().split("：").collect::<Vec<&str>>()[1].to_string()
            );
        } else if li_text.starts_with("類型") {
            vul_info.insert(
                String::from("type"),
                li_text.to_string().split("：").collect::<Vec<&str>>()[1].to_string()
            );
        }
    }
    return vul_info;
}

fn parse_block(document: &Document) -> bool {
    let base_url = Url::parse("https://zeroday.hitcon.org/").expect("Parse url error");
    let yesterday: Date<Local> = (Local::now() - Duration::days(1)).date();
    let mut result: bool = true;
    for node in document.find(And(Name("li"), Attr("class", "strip"))) {
        let report_path = node.find(Class("title").descendant(Name("a")))
            .next()
            .unwrap()
            .attr("href")
            .unwrap();
        let vul_report_url = base_url.join(report_path).expect("Join url error");
        let vul_info = get_vul_info(&vul_report_url.as_str());

        let naivedate_last_update = NaiveDate::parse_from_str(vul_info.get("last_update").expect("last_update not exist"), "%Y/%m/%d").expect("Parse date error");
        let last_update = Local.from_local_date(&naivedate_last_update).unwrap();
        if last_update >= yesterday {
            println!("- report url: {}", vul_report_url);
            println!("\tTitle: {}", vul_info.get("title").expect("title not exist"));
            println!("\tLast update: {}", vul_info.get("last_update").expect("last_update not exist"));
            println!("\tStatus: {}", vul_info.get("status").expect("status not exist"));
            println!("\tRisk: {}", vul_info.get("risk").expect("risk not exist"));
            println!("\tType: {}", vul_info.get("type").expect("type not exist"));
        } else {
            result = false;
            break;
        }
    }
    return result;
}

fn parse_content(body: String) {
    let document = Document::from(body.as_str());
    let last_page_num = get_last_page_num(&document);
    println!("last_page_num: {}", last_page_num);

    for page in 1..last_page_num {
        let base_url = Url::parse("https://zeroday.hitcon.org/vulnerability/all/").expect("Parse url error");
        let page_url = base_url.join(&format!("page/{}", page)).expect("Join url error");
        println!("Page url: {}", page_url);
        let page_body = reqwest::blocking::get(page_url)
            .expect("Page not found")
            .text()
            .expect("Get page body error");
        let page_document = Document::from(page_body.as_str());
        if !parse_block(&page_document) {
            break;
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let hitcon_zeroday_all_url = "https://zeroday.hitcon.org/vulnerability/all";
    let res = reqwest::blocking::get(hitcon_zeroday_all_url)?;

    println!("Status for {}: {}", hitcon_zeroday_all_url, res.status());
    match res.status() {
        StatusCode::OK =>  parse_content(res.text()?),
        s => println!("Received response status: {:?}", s),
    }
    Ok(())
}
