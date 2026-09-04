// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_MULTISIGWALLETTESTS_H
#define BITCOIN_QT_TEST_MULTISIGWALLETTESTS_H

#include <QObject>
#include <QTest>

namespace interfaces {
class Node;
} // namespace interfaces

class MultisigWalletTests : public QObject
{
public:
    explicit MultisigWalletTests(interfaces::Node& node) : m_node(node) {}
    interfaces::Node& m_node;

    Q_OBJECT

private Q_SLOTS:
    void multisigWalletTests();
};

#endif // BITCOIN_QT_TEST_MULTISIGWALLETTESTS_H
