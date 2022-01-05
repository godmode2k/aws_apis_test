#!/usr/bin/python3
# coding: utf-8

# -------------------------------------------------------------------
# Purpose: AWS APIs Test: Bills
# Author: Ho-Jung Kim (godmode2k@hotmail.com)
# Filename: test_aws-cost-and-usage-report.py
# Date: Since December 29, 2021
#
#
# Source-based: https://github.com/hjacobs/aws-cost-and-usage-report
# Reference:
# - https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html
# - https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_GetDimensionValues.html
# - (Currency rates) https://quotation-api-cdn.dunamu.com/v1/forex/recent?codes=FRX.KRWUSD
#
#
# $ pip3 install boto3
#
# Credentials
# SEE: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html
#
# ~/.aws/credentials
# [default]
# aws_access_key_id = <YOUR_ACCESS_KEY>
# aws_secret_access_key = <YOUR_SECRET>
# 
# ~/.aws/config
# [default]
# region=us-east-1
# 
#
# Usage:
# $ python3 ./test_aws-cost-and-usage-report.py --datestart="2021-11-01" --dateend="2021-12-01"
#
#
# Note:
# - USE THIS AT YOUR OWN RISK
#
#
# License:
#
#*
#* Copyright (C) 2021 Ho-Jung Kim (godmode2k@hotmail.com)
#*
#* Licensed under the Apache License, Version 2.0 (the "License");
#* you may not use this file except in compliance with the License.
#* You may obtain a copy of the License at
#*
#*      http://www.apache.org/licenses/LICENSE-2.0
#*
#* Unless required by applicable law or agreed to in writing, software
#* distributed under the License is distributed on an "AS IS" BASIS,
#* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#* See the License for the specific language governing permissions and
#* limitations under the License.
#*
# -------------------------------------------------------------------



import argparse
import boto3
import datetime

import requests # for currency rates
import json
import traceback
import sys



"""
parser = argparse.ArgumentParser()
parser.add_argument('--days', type=int, default=30)

# Date
parser.add_argument('--datestart', type=str)
parser.add_argument('--dateend', type=str)

args = parser.parse_args()


now = datetime.datetime.utcnow()
start = (now - datetime.timedelta(days=args.days)).strftime('%Y-%m-%d')
end = now.strftime('%Y-%m-%d')


# FIXME: UTC +9 (South Korea)
# datetime.now() + timedelta(hours=9)
# Date
if args.datestart != None and args.dateend != None:
    start = args.datestart
    end = args.dateend


# to use a specific profile e.g. 'dev'
session = boto3.session.Session(profile_name='dev')
cd = session.client('ce', 'us-east-1')

results = []

token = None
while True:
    if token:
        kwargs = {'NextPageToken': token}
    else:
        kwargs = {}
    data = cd.get_cost_and_usage(TimePeriod={'Start': start, 'End':  end}, Granularity='DAILY', Metrics=['UnblendedCost'], GroupBy=[{'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}, {'Type': 'DIMENSION', 'Key': 'SERVICE'}], **kwargs)
    results += data['ResultsByTime']
    token = data.get('NextPageToken')
    if not token:
        break

print('\t'.join(['TimePeriod', 'LinkedAccount', 'Service', 'Amount', 'Unit', 'Estimated']))
for result_by_time in results:
    for group in result_by_time['Groups']:
        amount = group['Metrics']['UnblendedCost']['Amount']
        unit = group['Metrics']['UnblendedCost']['Unit']
        print(result_by_time['TimePeriod']['Start'], '\t', '\t'.join(group['Keys']), '\t', amount, '\t', unit, '\t', result_by_time['Estimated'])
"""



KRW_USD = float(0)

# Currency rates (KRW/USD)
# FIXME: Replace with Exchange rates (for AWS invoice)
def calc_currency_exchange(amount):
    URL = "https://quotation-api-cdn.dunamu.com/v1/forex/recent?codes=FRX.KRWUSD"
    DATA = ""
    HEADERS = ""

    #KRW_USD = float(0)
    global KRW_USD

    try:
        #res = requests.post( URL, data = DATA, headers = HEADERS )
        res = requests.get( URL )
        #print( res.text )
        res_currency_rates = json.loads( str(res.text) )
        #print( currency_rates )
        KRW_USD = float( res_currency_rates[0]["basePrice"] )
        #print( "KRW/USD", KRW_USD )
    except Exception as e:
        traceback.print_exc()
        sys.exit(0)

    return float(amount * KRW_USD)



def get_cost_and_usage(start, end):
    global KRW_USD

    # to use a specific profile e.g. 'dev'
    #session = boto3.session.Session(profile_name='dev')
    session = boto3.session.Session()
    #cd = session.client('ce', 'us-east-1') # FIXME
    cd = session.client('ce')

    results = []

    token = None
    while True:
        if token:
            kwargs = {'NextPageToken': token}
        else:
            kwargs = {}
        #data = cd.get_cost_and_usage(TimePeriod={'Start': start, 'End':  end}, Granularity='DAILY', Metrics=['UnblendedCost'], GroupBy=[{'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}, {'Type': 'DIMENSION', 'Key': 'SERVICE'}], **kwargs)
        #
        # USE THIS
        data = cd.get_cost_and_usage(TimePeriod={'Start': start, 'End':  end}, Granularity='MONTHLY', Metrics=['AmortizedCost'], GroupBy=[{'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}, {'Type': 'DIMENSION', 'Key': 'SERVICE'}], **kwargs)
        #
        #data = cd.get_cost_and_usage(TimePeriod={'Start': start, 'End':  end}, Granularity='MONTHLY', Metrics=['AmortizedCost'], GroupBy=[{'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'}, {'Type': 'DIMENSION', 'Key': 'INVOICING_ENTITY'}], **kwargs)
        #
        results += data['ResultsByTime']
        token = data.get('NextPageToken')
        if not token:
            break



    total_amount_usd = float(0)
    total_group_amount_usd = {}
    unit = "USD"
    total_account = {}

    print( "Date:", start, "~", end )
    #print('\t'.join(['TimePeriod', 'LinkedAccount', 'Service', 'Amount', 'Unit', 'Estimated']))
    print('\t'.join(['LinkedAccount', 'Desc', 'Service', 'Amount', 'Unit', 'Estimated']))
    for result_by_time in results:
        #print( result_by_time )
        #print( result_by_time['TimePeriod']['Start'] )
        tmp_list = {}
        for group in result_by_time['Groups']:
            #amount = group['Metrics']['UnblendedCost']['Amount']
            #unit = group['Metrics']['UnblendedCost']['Unit']
            #
            # USE THIS
            amount = group['Metrics']['AmortizedCost']['Amount']
            unit = group['Metrics']['AmortizedCost']['Unit']
            #
            #print(result_by_time['TimePeriod']['Start'], '\t', '\t'.join(group['Keys']), '\t', amount, '\t', unit, '\t', result_by_time['Estimated'])
            # result:
            # 2021-12-28       758109260971   AWS CloudTrail   0.0     USD     True
            # ...


            #amount = float( "{:.2f}".format(float(amount)) )
            amount = float( amount ) # FIXME: exponent value

            key_account = str( group["Keys"][0] )
            val_service = str( group["Keys"][1] )

            # get_dimension_values()
            # result = {'DimensionValues': [{'Value': '<id>', 'Attributes': {'description': '<desc>'}}], ...
            _response = cd.get_dimension_values( TimePeriod={'Start': start, 'End':  end}, SearchString=key_account, Dimension='LINKED_ACCOUNT', Context='COST_AND_USAGE' )
            key_account_desc = str( _response['DimensionValues'][0]['Attributes']['description'] )
            #
            #for account_desc in _response['DimensionValues']
            #    key_account_desc = account_desc['Attributes']['description']
            #    break

            if not key_account in tmp_list:
                tmp_list[key_account] = {}
                tmp_list[key_account]["desc"] = key_account_desc
                tmp_list[key_account]["total_amount"] = float(0)
                tmp_list[key_account]["services"] = []

            if not key_account in total_group_amount_usd:
                total_group_amount_usd[key_account] = {}
                total_group_amount_usd[key_account]["desc"] = key_account_desc
                total_group_amount_usd[key_account]["total_amount"] = float(0)
                total_group_amount_usd[key_account]["services"] = []

            tmp_list[key_account]["services"].append( {"service": val_service, "amount": amount} )


        # sum
        # ---------------------------------

        # new services
        for key in total_group_amount_usd:
            # not found services for account
            #
            # add new one
            if len(total_group_amount_usd[key]["services"]) <= 0:
                total_group_amount_usd[key]["services"] = tmp_list[key]["services"].copy()

                # calc sum
                for i in range(len(tmp_list[key]["services"])):
                    total_group_amount_usd[key]["total_amount"] += float(tmp_list[key]["services"][i]["amount"])

                continue


            # exist services for account
            #
            # checks exist service with new items (service), insert new one if not found
            if not key in tmp_list:
                continue

            found = False
            for i in range(len(tmp_list[key]["services"])):
                for j in range(len(total_group_amount_usd[key]["services"])):
                    found = False
                    if total_group_amount_usd[key]["services"][j]["service"] == tmp_list[key]["services"][i]["service"]:
                        found = True
                        break

                # add new service
                if found == False:
                    tmp = tmp_list[key]["services"][i].copy()
                    tmp["amount"] = float(0)
                    total_group_amount_usd[key]["services"].append( tmp.copy() )
                    print( "add new:", tmp_list[key]["services"][i]["service"], "->", tmp )

            for i in range(len(tmp_list[key]["services"])):
                for j in range(len(total_group_amount_usd[key]["services"])):
                    if total_group_amount_usd[key]["services"][j]["service"] == tmp_list[key]["services"][i]["service"]:
                        total_group_amount_usd[key]["services"][j]["amount"] += float(tmp_list[key]["services"][i]["amount"])
    
                        total_group_amount_usd[key]["total_amount"] += float(tmp_list[key]["services"][i]["amount"])


    # --------------------------------------------


    for key in total_group_amount_usd:
        key_desc = total_group_amount_usd[key]["desc"]
        for i in range(len(total_group_amount_usd[key]["services"])):
            #print( key,
            #        '\t', total_group_amount_usd[key]["services"][i]["service"],
            #        '\t', total_group_amount_usd[key]["services"][i]["amount"],
            #        '\t', unit)
            service = str( total_group_amount_usd[key]["services"][i]["service"] )
            amount = str( total_group_amount_usd[key]["services"][i]["amount"] )
            dot_index = amount.index(".")
            #if (dot_index + 3) >= len(str(amount)):
            amount = amount[:(dot_index+3)] # .xx
            print( key, '\t', key_desc, '\t', "%-*s     %s" % (40, service, amount), '\t', unit )
    
        print( key, "total = ", total_group_amount_usd[key]["total_amount"] )
        total_amount_usd += float( total_group_amount_usd[key]["total_amount"] )


    print( "--------------------" )
    print( "Total:" )
    #print( f'Total: ${total_amount_usd:.2f}' )
    dot_index = str(total_amount_usd).index(".")
    print( "USD: $" + str('{0:,}'.format(float(str(total_amount_usd)[:(dot_index+3)]))) ) # .xx
    amount_krw = calc_currency_exchange( float(str(total_amount_usd)[:(dot_index+3)]) )
    print( "KRW: " + str('{0:,}'.format(amount_krw)) + " Won", "(KRW/USD: " + str(KRW_USD) + ")" )



#def textract_



if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Date
    parser.add_argument('--datestart', type=str)
    parser.add_argument('--dateend', type=str)

    args = parser.parse_args()

    # Date
    if args.datestart != None and args.dateend != None:
        start = args.datestart
        end = args.dateend


    # UTC +9 (South Korea)
    # datetime.now() + timedelta(hours=9)

    # Date: YY-MM-DD (2021-12-01)
    # 1 month (11)
    #start = "2021-11-01"
    #end = "2021-12-01"

    get_cost_and_usage( start, end )


