import './RiskBadge.css';

function RiskBadge({ level }) {
    const getBadgeClass = () => {
        switch (level?.toUpperCase()) {
            case 'HIGH':
                return 'badge badge-high';
            case 'MEDIUM':
                return 'badge badge-medium';
            case 'LOW':
                return 'badge badge-low';
            default:
                return 'badge';
        }
    };

    return <span className={getBadgeClass()}>{level || 'UNKNOWN'}</span>;
}

export default RiskBadge;
